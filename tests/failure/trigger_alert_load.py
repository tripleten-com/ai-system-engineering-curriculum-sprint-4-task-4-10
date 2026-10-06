"""Coldline.

===================

File:              tests/failure/trigger_alert_load.py
Component:         Failure tools — Trigger alert load
Purpose:           Force one exception to the dead-letter queue, then prove the alert fires.
Interacts With:    The API, LocalStack SQS, Docker Compose, Prometheus, Alertmanager
Sprint/Task:       Sprint 3 — Project 3
Concepts:          SLO/alert, dead-letter redrive, deterministic infrastructure, evidence
Tools:             Python 3.12, boto3, httpx, Docker Compose
"""

import json
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

import httpx

from tests.failure.force_dlq_arrival import DEAD_LETTER_NAME, QUEUE_NAME
from tests.failure.forcing_timing import emit, forcing_line
from tests.failure.queue_client import client, exhaust_receive_budget, queue_counts, queue_url
from tests.runtime_config import host_port

TASK_ROOT = Path(__file__).resolve().parents[2]
ALERT_NAME = "ColdlineDeadLetterQueueBacklog"
# Long enough to clear a correctly configured alert's `for` plus scrape and
# evaluation slack; short enough that the starter's 90s window cannot fire
# within it. See docs/student/task-3-4-contract.md for the published bound.
ACTIVE_WAIT_SECONDS = 45.0
POLL_INTERVAL_SECONDS = 2.0


def _build_reading() -> dict[str, Any]:
    """Build one exercise reading with a fresh identity per run.

    A fresh identity on every call keeps the automated slo-contract check and
    a student's own manual run from ever colliding on
    ReadingApplication's idempotent replay of the same reading_id.

    The API derives the exception identity as a deterministic hash of
    `reading_id` alone (`src/domain/exceptions.py::exception_id_for`), and
    `ReadingApplication.accept` intentionally returns the existing record
    without republishing once that identity is no longer `RECEIVED`
    (`src/api/use_cases.py`) — correct idempotent-replay behavior. Reusing a
    fixed identity here would make `poe slo-contract` (which runs this exact
    script internally) and any later manual `poe trigger-alert-load` collide
    on that same identity instead of each forcing a genuinely new exception.
    """
    token = uuid.uuid4().hex[:12]
    return {
        "reading_id": f"reading-alert-exercise-{token}",
        "shipment_id": f"shipment-alert-exercise-{token}",
        "temperature_c": 11.4,
        "allowed_min_c": 2.0,
        "allowed_max_c": 8.0,
        "recorded_at": "2026-01-01T00:00:00Z",
        "context": "Sprint 3 Task 3.4 SLO/alert exercise",
    }


def main() -> int:
    """Force one exception to the dead-letter queue, then wait for the alert to fire.

    The worker must already be stopped (`poe worker-stop`): forcing a message
    to the dead-letter queue receives it without acknowledging it, and a live
    worker would otherwise win the race and process it normally, exactly like
    `tests/failure/force_dlq_arrival.py`. This script then restarts the worker
    itself, because the dead-letter depth gauge
    (`src/worker/queue_monitor.py`) only reports while the worker process is
    running, and Prometheus can only evaluate the alert against a reading it
    is actually receiving. `poe verify-alert-recovery` expects the worker
    already running, which is why this script — not a separate manual step —
    restarts it.
    """
    api_port = host_port("COLDLINE_API_HOST_PORT", 8000)
    with httpx.Client(base_url=f"http://localhost:{api_port}", timeout=5.0) as api:
        accepted = api.post("/api/v1/readings", json=_build_reading())
        accepted.raise_for_status()
        exception_id = accepted.json()["exception_id"]

    sqs = client()
    main_url = queue_url(sqs, name=QUEUE_NAME)
    dlq_url = queue_url(sqs, name=DEAD_LETTER_NAME)
    max_receive_count = _max_receive_count(sqs, main_url)

    # Receives without acknowledging until SQS redrives the message; see
    # `exhaust_receive_budget` for why an empty first receive keeps polling.
    # This all happens before the worker restarts, so it never spends any of
    # the alert wait below.
    forcing = exhaust_receive_budget(sqs, main_url, max_receive_count=max_receive_count)

    dlq_depth = int(
        sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=["ApproximateNumberOfMessages"])[
            "Attributes"
        ]["ApproximateNumberOfMessages"]
    )
    # One timing line per forcing, printed on success too; see forcing_timing.py.
    outcome = "dead_lettered" if dlq_depth >= 1 else "not_dead_lettered"
    emit(forcing_line("trigger_alert_load", forcing, outcome=outcome))
    if dlq_depth < 1:
        print(
            json.dumps(
                {
                    "exception_id": exception_id,
                    "dead_letter_queue_depth": dlq_depth,
                    "alert_state": "not_dead_lettered",
                    "max_receive_count": max_receive_count,
                    "main_queue": queue_counts(sqs, main_url),
                    **forcing,
                },
                indent=2,
            )
        )
        return 1

    subprocess.run(["docker", "compose", "start", "worker"], cwd=TASK_ROOT, check=True)

    alert_state, active_since = wait_for_alert_state(target_state="active")

    print(
        json.dumps(
            {
                "exception_id": exception_id,
                "dead_letter_queue_depth": dlq_depth,
                "alert_state": alert_state,
                "active_since": active_since,
                **forcing,
            },
            indent=2,
        )
    )
    return 0 if alert_state == "active" else 1


def alertmanager_base_url() -> str:
    """Return Alertmanager's host-reachable base URL."""
    port = host_port("COLDLINE_ALERTMANAGER_HOST_PORT", 9093)
    return f"http://localhost:{port}"


def find_alert(alerts: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Return this Task's one named alert from an Alertmanager API listing, if present."""
    for alert in alerts:
        if alert.get("labels", {}).get("alertname") == ALERT_NAME:
            return alert
    return None


def wait_for_alert_state(
    *, target_state: str, timeout_seconds: float = ACTIVE_WAIT_SECONDS
) -> tuple[str, str | None]:
    """Poll Alertmanager's own API until the alert reaches the target state, or time out.

    Shared with `tests/failure/verify_alert_recovery.py`, which polls for
    ``"resolved"`` after redrive instead of ``"active"`` after the forced
    failure. On timeout it returns the last state it observed, so a caller
    never mistakes a timeout for the state it was waiting for:
    ``("absent", None)`` when Alertmanager never listed the alert (a too-long
    `for` value keeps Prometheus's rule pending, so Alertmanager never
    receives it at all), or ``("active", <startsAt>)`` when a redrive left the
    alert firing.
    """
    deadline = time.monotonic() + timeout_seconds
    last_state, last_starts_at = "absent", None
    with httpx.Client(base_url=alertmanager_base_url(), timeout=5.0) as alertmanager:
        while time.monotonic() < deadline:
            response = alertmanager.get("/api/v2/alerts")
            response.raise_for_status()
            alert = find_alert(response.json())
            if alert is not None:
                state = alert.get("status", {}).get("state")
                if state == target_state:
                    return state, alert.get("startsAt")
                last_state, last_starts_at = state or "absent", alert.get("startsAt")
            elif target_state == "resolved":
                # An alert Alertmanager has fully forgotten also counts as resolved.
                return "absent", None
            else:
                last_state, last_starts_at = "absent", None
            time.sleep(POLL_INTERVAL_SECONDS)
    return last_state, last_starts_at


def _max_receive_count(sqs: Any, url: str) -> int:
    """Read the deployed redrive policy's bound from the live queue."""
    attributes = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["RedrivePolicy"])[
        "Attributes"
    ]
    policy = json.loads(attributes["RedrivePolicy"])
    return int(policy["maxReceiveCount"])


if __name__ == "__main__":
    raise SystemExit(main())
