"""Coldline.

===================

File:              tests/failure/force_dlq_arrival.py
Component:         Failure tools — Force dead-letter arrival
Purpose:           Submit one real exception, then force it to the dead-letter queue.
Interacts With:    The API, LocalStack SQS
Sprint/Task:       Sprint 3 — Project 3
Concepts:          Dead-letter redrive, deterministic infrastructure, evidence
Tools:             Python 3.12, boto3, httpx
"""

import json
from typing import Any
from uuid import uuid4

import httpx

from tests.failure.forcing_timing import emit, forcing_line
from tests.failure.queue_client import client, exhaust_receive_budget, queue_counts, queue_url
from tests.runtime_config import host_port

QUEUE_NAME = "coldline-exception-jobs"
DEAD_LETTER_NAME = "coldline-exception-jobs-dlq"
READING_TEMPLATE = {
    "shipment_id": "shipment-dlq-exercise-001",
    "temperature_c": 11.4,
    "allowed_min_c": 2.0,
    "allowed_max_c": 8.0,
    "recorded_at": "2026-01-01T00:00:00Z",
    "context": "Sprint 3 Task 3.3 dead-letter exercise",
}


def _max_receive_count(sqs: Any, url: str) -> int:
    """Read the deployed redrive policy's bound from the live queue."""
    attributes = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["RedrivePolicy"])[
        "Attributes"
    ]
    policy = json.loads(attributes["RedrivePolicy"])
    return int(policy["maxReceiveCount"])


def main() -> int:
    """Submit one exception, then simulate its transport-level exhaustion.

    The worker must be stopped before running this
    (`docker compose --profile observability --profile localstack stop worker`),
    so nothing else races to process the message while this script repeatedly
    receives it without acknowledging it. Each receive-without-delete leaves
    SQS's own visibility timeout to elapse before the message becomes visible
    again; `change_message_visibility` collapses that wait to make the exercise
    deterministic instead of waiting for real time to pass.
    """
    # A fresh reading per run, so a rerun creates a new exception instead of
    # replaying the last one: the API returns an existing identity without
    # publishing it again, which would leave nothing here to dead-letter.
    reading = {"reading_id": f"reading-dlq-exercise-{uuid4().hex[:12]}", **READING_TEMPLATE}
    api_port = host_port("COLDLINE_API_HOST_PORT", 8000)
    with httpx.Client(base_url=f"http://localhost:{api_port}", timeout=5.0) as api:
        accepted = api.post("/api/v1/readings", json=reading)
        accepted.raise_for_status()
        exception_id = accepted.json()["exception_id"]

    sqs = client()
    main_url = queue_url(sqs, name=QUEUE_NAME)
    dlq_url = queue_url(sqs, name=DEAD_LETTER_NAME)
    max_receive_count = _max_receive_count(sqs, main_url)

    # Receives without acknowledging until SQS redrives the message; see
    # `exhaust_receive_budget` for why an empty first receive keeps polling.
    forcing = exhaust_receive_budget(sqs, main_url, max_receive_count=max_receive_count)

    dlq_depth = int(
        sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=["ApproximateNumberOfMessages"])[
            "Attributes"
        ]["ApproximateNumberOfMessages"]
    )
    # One timing line per forcing, printed on success too; see forcing_timing.py.
    outcome = "dead_lettered" if dlq_depth >= 1 else "not_dead_lettered"
    emit(forcing_line("force_dlq_arrival", forcing, outcome=outcome))
    evidence: dict[str, Any] = {
        "exception_id": exception_id,
        "max_receive_count": max_receive_count,
        "dead_letter_queue_depth": dlq_depth,
    }
    if dlq_depth < 1:
        # Where the message is instead.
        evidence.update(main_queue=queue_counts(sqs, main_url))
    # How the forcing loop saw it, on success and failure alike.
    evidence.update(forcing)
    print(json.dumps(evidence, indent=2))
    return 0 if dlq_depth >= 1 else 1


if __name__ == "__main__":
    raise SystemExit(main())
