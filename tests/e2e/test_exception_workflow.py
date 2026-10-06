"""Coldline.

===================

File:              tests/e2e/test_exception_workflow.py
Component:         End-to-end tests — Exception workflow
Purpose:           Proves the external API-to-worker behavior, the durable duplicate identity,
                    and the one joined trace an exception-resolution request leaves behind.
Interacts With:    API, worker, PostgreSQL, LocalStack SQS, and Jaeger
Sprint/Task:       Sprint 4 — Project 4
Concepts:          Asynchronous completion, idempotency, observable evidence, trace continuity
Tools:             Python 3.12, pytest, httpx

From Task 4.2 every read of the status resource sends the ``dispatcher-valid`` token
fixture, so these checks pass while the route is still open and once it is protected.
From Task 4.4 the handling-note check pins what the API path keeps (the note as typed)
and what the summary carries (a handling-note sentence and the procedure), not the
sentence's exact content: the worker's redaction of that sentence is the Task's work, and
this check holds on the starter and on a completion alike.
"""

import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from urllib.parse import quote
from uuid import uuid4

import httpx
import pytest

from tests.runtime_config import host_port
from tests.security.fixtures import bearer_headers

TASK_ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.runtime
# One span per workflow element the threat model names, by operation name as Jaeger
# shows it. The API's own server span is named after the route by the FastAPI
# instrumentation and is matched by prefix below.
WORKFLOW_SPANS = {
    "job_queue.publish": "queue",
    "coldline.process_exception": "worker",
    "retriever.search_hybrid": "retriever",
    "model_provider.summarize": "model provider",
    "postgres.exceptions.transition": "exception records",
}
API_SERVER_SPAN_PREFIX = "POST /api/v1/readings"
WORKFLOW_SERVICES = {"coldline-api", "coldline-worker"}
# Each service's exporter flushes on its own schedule, so Jaeger can show a joined
# trace with the API's spans, or the worker's provider span, before the worker's
# processing span or its final database span has arrived. The joined-trace check
# therefore polls until the trace is complete, and reports what is missing only once
# this deadline has passed.
JOINED_TRACE_DEADLINE_SECONDS = 20.0


def _load_unique_reading() -> tuple[str, dict[str, Any]]:
    """Return the supplied synthetic reading with a unique test identity."""
    fixture = json.loads(
        (TASK_ROOT / "tests/e2e/baseline-exception.json").read_text(encoding="utf-8")
    )
    reading = cast(dict[str, Any], fixture["reading"])
    suffix = uuid4().hex
    reading["reading_id"] = f"reading-e2e-{suffix}"
    reading["shipment_id"] = f"shipment-e2e-{suffix}"
    reading["recorded_at"] = datetime.now(UTC).isoformat()
    return cast(str, fixture["scenario_id"]), reading


def _wait_for_terminal(client: httpx.Client, status_url: str) -> dict[str, Any]:
    """Poll the public status resource, as the dispatcher, until the workflow becomes terminal."""
    for _ in range(40):
        response = client.get(status_url, headers=bearer_headers("dispatcher-valid"))
        response.raise_for_status()
        record = cast(dict[str, Any], response.json())
        if record["state"] == "COMPLETED":
            return record
        if record["state"] == "FAILED":
            pytest.fail("the supplied workflow reached FAILED")
        time.sleep(0.5)
    pytest.fail("the supplied workflow did not complete within 20 seconds")


def _service_traces(service: str, exception_id: str) -> list[dict[str, Any]]:
    """Return Jaeger's traces for one service and durable exception identity, right now."""
    jaeger_port = host_port("COLDLINE_JAEGER_HOST_PORT", 16686)
    tags = quote(json.dumps({"coldline.exception_id": exception_id}, separators=(",", ":")))
    endpoint = f"http://localhost:{jaeger_port}/api/traces?service={service}&tags={tags}"
    response = httpx.get(endpoint, timeout=5.0)
    response.raise_for_status()
    return cast(list[dict[str, Any]], response.json().get("data", []))


def _wait_for_service_evidence(service: str, exception_id: str) -> list[dict[str, Any]]:
    """Return Jaeger evidence for one service and durable exception identity."""
    for _ in range(30):
        traces = _service_traces(service, exception_id)
        if traces:
            return traces
        time.sleep(0.5)
    return []


def _trace_ids(traces: list[dict[str, Any]]) -> set[str]:
    """Return the distinct trace identities in one Jaeger answer."""
    return {cast(str, item["traceID"]) for item in traces}


def _spans(traces: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flatten every span, with its service name attached, from one Jaeger answer.

    Two answers for the same trace can each hold spans the other lacks while the
    exporters are still flushing, so spans are deduplicated by identity.
    """
    spans: dict[tuple[str, str], dict[str, Any]] = {}
    for item in traces:
        processes = cast(dict[str, Any], item.get("processes", {}))
        for span in item["spans"]:
            process = cast(dict[str, Any], processes.get(span.get("processID", ""), {}))
            key = (cast(str, span["traceID"]), cast(str, span["spanID"]))
            spans[key] = {**span, "service": process.get("serviceName", "")}
    return list(spans.values())


def _joined_trace_is_complete(operations: set[str], services: set[str]) -> bool:
    """Return whether a joined trace shows both services, the API route, and every element."""
    return (
        WORKFLOW_SERVICES <= services
        and any(name.startswith(API_SERVER_SPAN_PREFIX) for name in operations)
        and set(WORKFLOW_SPANS) <= operations
    )


def _wait_for_joined_trace(exception_id: str) -> tuple[bool, bool, set[str], set[str], set[str]]:
    """Poll Jaeger until one trace shared by both services is complete, or the deadline passes.

    Returns whether each service exported anything, the trace ids both share,
    and the operations and services seen in those shared traces. Completeness
    is both services, the API's server span, and every ``WORKFLOW_SPANS``
    operation; until the deadline a shortfall is treated as spans still in
    flight, not as a missing element.
    """
    deadline = time.monotonic() + JOINED_TRACE_DEADLINE_SECONDS
    while True:
        api_traces = _service_traces("coldline-api", exception_id)
        worker_traces = _service_traces("coldline-worker", exception_id)
        joined = _trace_ids(api_traces) & _trace_ids(worker_traces)
        spans = [span for span in _spans(api_traces + worker_traces) if span["traceID"] in joined]
        operations = {cast(str, span["operationName"]) for span in spans}
        services = {cast(str, span["service"]) for span in spans}
        if _joined_trace_is_complete(operations, services) or time.monotonic() >= deadline:
            return bool(api_traces), bool(worker_traces), joined, operations, services
        time.sleep(0.5)


def test_exception_workflow_completes_with_stable_duplicate_identity() -> None:
    """Catch lost work, unstable idempotency, or missing API and worker evidence."""
    scenario_id, reading = _load_unique_reading()
    api_port = host_port("COLDLINE_API_HOST_PORT", 8000)
    with httpx.Client(base_url=f"http://localhost:{api_port}", timeout=5.0) as client:
        accepted = client.post("/api/v1/readings", json=reading)
        assert accepted.status_code == 202
        first = cast(dict[str, Any], accepted.json())
        record = _wait_for_terminal(client, cast(str, first["status_url"]))

        duplicate = client.post("/api/v1/readings", json=reading)
        assert duplicate.status_code == 202
        replay = cast(dict[str, Any], duplicate.json())

        status = client.get(
            cast(str, first["status_url"]), headers=bearer_headers("dispatcher-valid")
        )
        status.raise_for_status()

    assert scenario_id == "sprint1-baseline-exception"
    assert record["state"] == "COMPLETED"
    assert replay["exception_id"] == first["exception_id"]
    assert replay["status_url"] == first["status_url"]
    assert status.json()["exception_id"] == first["exception_id"]
    assert _wait_for_service_evidence("coldline-api", cast(str, first["exception_id"]))
    assert _wait_for_service_evidence("coldline-worker", cast(str, first["exception_id"]))


def test_handling_note_reaches_the_stored_reading_and_the_summary_names_the_procedure() -> None:
    """The stored reading keeps the note as typed; the summary carries a note and the procedure.

    The API path redacts nothing: the reading is stored as it arrived, and that is the
    residual the Task 4 lesson names (the stored reading and the queued job keep the raw
    note). The summary ends with a handling-note sentence and names the retrieved
    procedure; what that sentence holds is the worker's work from Task 4.4 (the supplied
    redactor's output on a completion, the note as written on the starter), so this check
    does not pin it.
    """
    _, reading = _load_unique_reading()
    api_port = host_port("COLDLINE_API_HOST_PORT", 8000)
    with httpx.Client(base_url=f"http://localhost:{api_port}", timeout=5.0) as client:
        accepted = client.post("/api/v1/readings", json=reading)
        assert accepted.status_code == 202
        record = _wait_for_terminal(client, cast(str, accepted.json()["status_url"]))

    stored_reading = cast(dict[str, Any], record["reading"])
    assert stored_reading["handling_note"] == reading["handling_note"]
    summary = cast(str, record["summary"])
    assert "Handling note: " in summary, summary
    assert "Procedure " in summary, summary


def test_worker_continues_the_api_trace_with_a_span_for_every_workflow_element() -> None:
    """One request leaves one trace, and that trace shows each element the threat model names.

    The API starts the trace, the queue carries it, and the worker continues it:
    the worker's spans sit in the API's trace rather than in one of their own.
    The spans named in ``WORKFLOW_SPANS`` must all be present so a student can
    match the trace to the elements in ``docs/security/workflow.md``. Jaeger is
    polled until the shared trace is complete or the deadline passes, so a span
    still being exported is not reported as missing.
    """
    _, reading = _load_unique_reading()
    api_port = host_port("COLDLINE_API_HOST_PORT", 8000)
    with httpx.Client(base_url=f"http://localhost:{api_port}", timeout=5.0) as client:
        accepted = client.post("/api/v1/readings", json=reading)
        assert accepted.status_code == 202
        exception_id = cast(str, accepted.json()["exception_id"])
        _wait_for_terminal(client, cast(str, accepted.json()["status_url"]))

    api_exported, worker_exported, joined, operations, services = _wait_for_joined_trace(
        exception_id
    )
    assert api_exported and worker_exported, "both services must export trace evidence"
    assert joined, "the worker started its own trace instead of continuing the API's"

    missing = sorted(name for name in WORKFLOW_SPANS if name not in operations)
    assert not missing, f"spans missing from the joined trace: {missing}; found {operations}"
    assert any(name.startswith(API_SERVER_SPAN_PREFIX) for name in operations), operations
    assert services == WORKFLOW_SERVICES, services
