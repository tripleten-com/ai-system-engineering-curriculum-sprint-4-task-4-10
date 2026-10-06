"""Coldline.

===================

File:              tests/e2e/scenario.py
Component:         End-to-end tests — Scenario
Purpose:           Run the supplied baseline exception scenario with one of the emulator's
                    supplied responses and, optionally, one of the supplied handling notes.
Interacts With:    External API, worker, storage, and telemetry; tests/fixtures/pii/notes.yaml
Sprint/Task:       Sprint 4 — Project 4 / Task 4.4
Concepts:          Black-box workflow, durable identity, evidence, supplied bad answers,
                    supplied notes
Tools:             Python 3.12, pytest

From Task 4.2 the status URL is read with the ``dispatcher-valid`` token fixture. From Task
4.3 ``--response valid|malformed|manipulated`` selects the emulator's answer. From Task 4.4
``--response pii-echo`` is a fourth answer, and ``--note <id>`` replaces the reading's
handling note with one of the supplied notes in ``tests/fixtures/pii/notes.yaml``; the two
options combine. The reading is sent with a fresh identity each run, so every run is a new
exception, and the selector travels in the reading's ``emulator_response`` field. The
scenario waits for a finished state (``COMPLETED`` or ``NEEDS_REVIEW``), prints the state
with the exception and trace ids, and that one read of the finished record is itself a
summary read in the audit trail. The exception id it prints is what ``poe pii-scan`` takes.
"""

import argparse
import json
import time
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from urllib.parse import quote
from uuid import uuid4

import httpx

from adapters.model.deterministic import RESPONSES
from tests.runtime_config import host_port
from tests.security import pii
from tests.security.fixtures import bearer_headers

TASK_ROOT = Path(__file__).resolve().parents[2]
FINISHED_STATES = {"COMPLETED", "NEEDS_REVIEW"}


def main(argv: Sequence[str] = ()) -> int:
    """Run one exception with the chosen supplied response and note; print its references."""
    parser = argparse.ArgumentParser(description="Run the supplied exception scenario.")
    parser.add_argument(
        "--response",
        choices=RESPONSES,
        default="valid",
        help="which supplied emulator response the model returns (default: valid)",
    )
    parser.add_argument(
        "--note",
        choices=pii.note_ids(TASK_ROOT),
        default=None,
        help="replace the reading's handling note with this supplied note (default: as shipped)",
    )
    arguments = parser.parse_args(list(argv))
    fixture = json.loads(
        (TASK_ROOT / "tests/e2e/baseline-exception.json").read_text(encoding="utf-8")
    )
    note = None if arguments.note is None else pii.note_text(arguments.note, TASK_ROOT)
    reading = scenario_reading(fixture, response=arguments.response, note=note)
    api_port = host_port("COLDLINE_API_HOST_PORT", 8000)
    with httpx.Client(base_url=f"http://localhost:{api_port}", timeout=5.0) as client:
        accepted = client.post("/api/v1/readings", json=reading)
        accepted.raise_for_status()
        accepted_body = accepted.json()
        record = _wait_for_completion(client, accepted_body["status_url"])
        exception_id = cast(str, record["exception_id"])
        api_trace_id = _wait_for_traces(client, "coldline-api", exception_id)
        worker_trace_id = _wait_for_traces(client, "coldline-worker", exception_id)
    print(
        json.dumps(
            {
                "scenario_id": fixture["scenario_id"],
                "response": arguments.response,
                "note": arguments.note,
                "exception_id": record["exception_id"],
                "state": record["state"],
                "api_trace_id": api_trace_id,
                "worker_trace_id": worker_trace_id,
                "status_url": accepted_body["status_url"],
                "jaeger_url": (f"http://localhost:{host_port('COLDLINE_JAEGER_HOST_PORT', 16686)}"),
                "grafana_url": (
                    f"http://localhost:{host_port('COLDLINE_GRAFANA_HOST_PORT', 3000)}"
                    "/d/coldline-task-1-1"
                ),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def scenario_reading(
    fixture: dict[str, Any], *, response: str, note: str | None = None
) -> dict[str, Any]:
    """Return the supplied reading with a fresh identity, the response selector and the note.

    A fresh identity per run is what makes each run a new exception: the exception id is
    derived from the reading id, so re-sending the fixture's own ids would replay the
    first run's record whatever response was asked for. ``note`` is the text of a supplied
    note; None keeps the fixture's own handling note.
    """
    reading = dict(cast(dict[str, Any], fixture["reading"]))
    suffix = uuid4().hex[:12]
    reading["reading_id"] = f"reading-syn-{response}-{suffix}"
    reading["shipment_id"] = f"shipment-syn-{suffix}"
    reading["recorded_at"] = datetime.now(UTC).isoformat()
    reading["emulator_response"] = response
    if note is not None:
        reading["handling_note"] = note
    return reading


def _wait_for_completion(client: httpx.Client, status_url: str) -> dict[str, object]:
    """Poll the durable record until it reaches a finished state, as the dispatcher."""
    for _ in range(30):
        response = client.get(status_url, headers=bearer_headers("dispatcher-valid"))
        response.raise_for_status()
        record = response.json()
        if record["state"] in FINISHED_STATES:
            return cast(dict[str, object], record)
        if record["state"] == "FAILED":
            raise RuntimeError("published scenario reached FAILED; run `poe reset` and retry")
        time.sleep(0.5)
    raise RuntimeError("published scenario did not finish within 15 seconds")


def _wait_for_traces(client: httpx.Client, service: str, exception_id: str) -> str:
    """Return the most recent trace identity correlated to one exception when exported."""
    tags = quote(json.dumps({"coldline.exception_id": exception_id}, separators=(",", ":")))
    jaeger_port = host_port("COLDLINE_JAEGER_HOST_PORT", 16686)
    endpoint = f"http://localhost:{jaeger_port}/api/traces?service={service}&tags={tags}"
    for _ in range(20):
        response = client.get(endpoint)
        response.raise_for_status()
        traces = cast(list[dict[str, Any]], response.json().get("data", []))
        candidates: list[tuple[int, str]] = []
        for trace in traces:
            trace_id = trace.get("traceID")
            spans = trace.get("spans")
            if not isinstance(trace_id, str) or not isinstance(spans, list):
                continue
            start_times = [
                start_time
                for span in spans
                if isinstance(span, dict)
                if isinstance(start_time := span.get("startTime"), int)
            ]
            candidates.append((max(start_times, default=0), trace_id))
        if candidates:
            return max(candidates)[1]
        time.sleep(0.5)
    raise RuntimeError(f"no {service} trace was exported for exception {exception_id}")


if __name__ == "__main__":
    import sys

    raise SystemExit(main(sys.argv[1:]))
