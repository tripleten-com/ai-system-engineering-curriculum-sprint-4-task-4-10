"""Coldline.

===================

File:              tests/failure/dev_failure_lab.py
Component:         Failure tools — Development failure lab
Purpose:           Take the worker away for a bounded window, build a backlog, and prove recovery.
Interacts With:    The API, LocalStack SQS, Docker Compose
Sprint/Task:       Sprint 3 — Project 3
Concepts:          Consumer outage, queue backlog, idempotent recovery, evidence
Tools:             Python 3.12, boto3, httpx, Docker Compose

This is Task 3.6's development failure scenario. The fault is a bounded *consumer*
outage: the ``worker`` container is stopped, five fresh readings are submitted through the
API so a backlog builds on the main queue, and the worker is started again. The script
then waits for every submitted exception to reach ``COMPLETED`` and for both the main
queue and the dead-letter queue to return to zero, and prints one JSON evidence blob.

Be exact about what this fault does. A stopped consumer never *receives*, and SQS only
redrives a message after ``maxReceiveCount`` actual receive attempts, so stopping the
worker does not dead-letter anything by itself: messages accumulate on the main queue with
growing depth and zero in-flight count until the consumer returns. A message that was
mid-receive when the container stopped can, rarely, expire back onto the queue and count
one attempt. The lab tolerates that edge case - it redrives anything that does land in the
dead-letter queue, the same way ``redrive_and_verify.py`` does, before its final check -
but it never depends on it, and never asserts it.
"""

import json
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

import httpx

from tests.failure.force_dlq_arrival import DEAD_LETTER_NAME, QUEUE_NAME
from tests.failure.queue_client import client, queue_url
from tests.runtime_config import host_port
from tests.security.fixtures import bearer_headers

TASK_ROOT = Path(__file__).resolve().parents[2]
READING_COUNT = 5
# Long enough that the backlog is observable on the dashboard and in the queue attributes
# before the worker returns; short enough that the whole lab stays well under two minutes.
WORKER_STOPPED_SECONDS = 10.0
# Bounded recovery wait. Five readings at the supplied 250 ms model latency drain in a
# few seconds once the worker is back; the bound leaves room for the worker's own startup
# and, in the rare edge case, for one visibility-timeout redelivery (30 s).
RECOVERY_TIMEOUT_SECONDS = 120.0
POLL_INTERVAL_SECONDS = 2.0
TERMINAL_STATES = {"COMPLETED", "FAILED"}


def _build_reading() -> dict[str, Any]:
    """Build one exercise reading with a fresh identity per call.

    A fresh identity on every call keeps this lab's own runs, the Task 3.3 and 3.4 exercise
    scripts, and the automated checks from ever colliding on ``ReadingApplication``'s
    idempotent replay of the same ``reading_id``; see ``trigger_alert_load.py`` for why.
    """
    token = uuid.uuid4().hex[:12]
    return {
        "reading_id": f"reading-failure-lab-{token}",
        "shipment_id": f"shipment-failure-lab-{token}",
        "temperature_c": 11.4,
        "allowed_min_c": 2.0,
        "allowed_max_c": 8.0,
        "recorded_at": "2026-01-01T00:00:00Z",
        "context": "Sprint 3 Task 3.6 development failure lab",
    }


def _compose(*arguments: str) -> None:
    """Run one Docker Compose command from the Task root, exactly like the Poe targets do."""
    subprocess.run(["docker", "compose", *arguments], cwd=TASK_ROOT, check=True)


def _depths(sqs: Any, main_url: str, dlq_url: str) -> tuple[int, int]:
    """Return the approximate main-queue and dead-letter-queue depths, as SQS reports them."""
    depths = []
    for url in (main_url, dlq_url):
        attributes = sqs.get_queue_attributes(
            QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages"]
        )["Attributes"]
        depths.append(int(attributes["ApproximateNumberOfMessages"]))
    return depths[0], depths[1]


def _redrive_dead_letters(sqs: Any, main_url: str, dlq_url: str) -> int:
    """Move every dead-lettered message back to the main queue; return how many moved.

    The same receive/send/delete shape as ``redrive_and_verify.py``. Only reached in the
    rare edge case described in the module docstring; on the primary path the dead-letter
    queue stays empty throughout.
    """
    moved = 0
    while True:
        response = sqs.receive_message(QueueUrl=dlq_url, MaxNumberOfMessages=10, WaitTimeSeconds=1)
        messages = response.get("Messages") or []
        if not messages:
            return moved
        for message in messages:
            sqs.send_message(QueueUrl=main_url, MessageBody=message["Body"])
            sqs.delete_message(QueueUrl=dlq_url, ReceiptHandle=message["ReceiptHandle"])
            moved += 1


def main() -> int:
    """Stop the worker, build a backlog, restart the worker, and prove full recovery.

    Run this against a stack ``poe start`` already brought up, with the worker running. The
    script stops and starts the worker itself; it does not touch any other service. Exit 0
    means every submitted reading reached ``COMPLETED`` and both queue depths are zero.
    """
    api_port = host_port("COLDLINE_API_HOST_PORT", 8000)
    sqs = client()
    main_url = queue_url(sqs, name=QUEUE_NAME)
    dlq_url = queue_url(sqs, name=DEAD_LETTER_NAME)
    readings = [_build_reading() for _ in range(READING_COUNT)]
    exception_ids: list[str] = []

    print("stopping the worker", flush=True)
    _compose("stop", "worker")
    try:
        with httpx.Client(base_url=f"http://localhost:{api_port}", timeout=10.0) as api:
            for reading in readings:
                accepted = api.post("/api/v1/readings", json=reading)
                accepted.raise_for_status()
                exception_ids.append(str(accepted.json()["exception_id"]))
            print(f"submitted {len(exception_ids)} readings with the worker stopped", flush=True)
            time.sleep(WORKER_STOPPED_SECONDS)
            stopped_depth, stopped_dlq_depth = _depths(sqs, main_url, dlq_url)
            print(
                f"while stopped: queue_depth={stopped_depth} dead_letter_depth={stopped_dlq_depth}",
                flush=True,
            )
    finally:
        # Whatever happened above, the worker comes back: a lab must never leave the
        # student's stack without its consumer.
        print("starting the worker", flush=True)
        _compose("start", "worker")

    started = time.monotonic()
    deadline = started + RECOVERY_TIMEOUT_SECONDS
    states: dict[str, str] = {}
    redriven = 0
    with httpx.Client(base_url=f"http://localhost:{api_port}", timeout=10.0) as api:
        while time.monotonic() < deadline:
            for exception_id in exception_ids:
                if exception_id in states:
                    continue
                # Read as the dispatcher: from Task 4.2 the summary endpoint requires it.
                response = api.get(
                    f"/api/v1/exceptions/{exception_id}",
                    headers=bearer_headers("dispatcher-valid"),
                )
                response.raise_for_status()
                state = str(response.json()["state"])
                if state in TERMINAL_STATES:
                    states[exception_id] = state
            queue_depth, dlq_depth = _depths(sqs, main_url, dlq_url)
            if dlq_depth > 0:
                # The rare edge case: a message that was mid-receive when the container
                # stopped, expired back onto the queue, and exhausted its receive budget.
                redriven += _redrive_dead_letters(sqs, main_url, dlq_url)
                print(f"redrove {redriven} dead-lettered message(s)", flush=True)
            if len(states) == len(exception_ids) and queue_depth == 0 and dlq_depth == 0:
                break
            print(
                f"recovering: terminal={len(states)}/{len(exception_ids)} "
                f"queue_depth={queue_depth} dead_letter_depth={dlq_depth}",
                flush=True,
            )
            time.sleep(POLL_INTERVAL_SECONDS)
    elapsed = round(time.monotonic() - started, 1)
    final_depth, final_dlq_depth = _depths(sqs, main_url, dlq_url)

    completed = all(states.get(exception_id) == "COMPLETED" for exception_id in exception_ids)
    recovered = completed and final_depth == 0 and final_dlq_depth == 0
    print(
        json.dumps(
            {
                "fault": "consumer_outage",
                "target_service": "worker",
                "worker_stopped_seconds": WORKER_STOPPED_SECONDS,
                "exception_ids": exception_ids,
                "queue_depth_while_stopped": stopped_depth,
                "dead_letter_depth_while_stopped": stopped_dlq_depth,
                "redriven_messages": redriven,
                "states": {
                    exception_id: states.get(exception_id) for exception_id in exception_ids
                },
                "final_queue_depth": final_depth,
                "final_dead_letter_depth": final_dlq_depth,
                "recovery_seconds": elapsed,
                "outcome": "recovered" if recovered else "not_recovered",
            },
            indent=2,
        )
    )
    return 0 if recovered else 1


if __name__ == "__main__":
    raise SystemExit(main())
