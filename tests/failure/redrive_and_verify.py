"""Coldline.

===================

File:              tests/failure/redrive_and_verify.py
Component:         Failure tools — Redrive and verify
Purpose:           Redrive the dead-lettered exercise messages and prove idempotent recovery.
Interacts With:    The API, LocalStack SQS
Sprint/Task:       Sprint 3 — Project 3
Concepts:          Dead-letter redrive, idempotent recovery, evidence
Tools:             Python 3.12, boto3, httpx
"""

import json
import sys
import time
from typing import Any

import httpx

from tests.failure.force_dlq_arrival import DEAD_LETTER_NAME, QUEUE_NAME
from tests.failure.queue_client import client, queue_counts, queue_url
from tests.runtime_config import host_port
from tests.security.fixtures import bearer_headers

# Each receive returns at most 10 messages. 100 batches covers any dead-letter
# queue these exercises can build up; reaching it means something keeps
# refilling the queue, so the run stops and says so instead of looping.
MAX_RECEIVE_BATCHES = 100
# A record the API no longer has, for example after `poe reset-baseline`
# emptied the table while an older message still sat in the dead-letter queue.
MISSING = "MISSING"


def main() -> int:
    """Redrive every dead-lettered message, then confirm the newest completes exactly once.

    Start the worker again before running this
    (`docker compose --profile observability --profile localstack start worker`).
    The redriven message is the *same* durable exception identity the injector
    submitted. Once it completes, the same job is delivered once more, as a
    duplicate redrive or an at-least-once redelivery would deliver it.
    `WorkerApplication` treats a delivery for an already-terminal identity as a
    safe replay, so the record must stay unchanged: that second delivery is what
    proves recovery is idempotent rather than merely that the message
    eventually got processed.

    The dead-letter queue can hold more than that one message: an earlier
    attempt, or another exercise's own forcing script, can leave its message
    behind. This script redrives them all, so none is left for the next run to
    pick up by mistake. It reports the most recently sent one, the message the
    injector just forced, as `exception_id`, replays only that one, and lists
    any older ones under `also_redriven`. An exception whose record the API no
    longer has is reported as `MISSING` and listed under `missing`; an older
    orphan like that does not fail the run. It exits `0` only when the reported
    exception and every other redriven exception that still has a record
    completed, and the replay left the reported record unchanged.
    """
    sqs = client()
    dlq_url = queue_url(sqs, name=DEAD_LETTER_NAME)
    main_url = queue_url(sqs, name=QUEUE_NAME)

    redriven, drained = _redrive_all(sqs, dlq_url, main_url)
    if not drained:
        print(
            f"stopped after {MAX_RECEIVE_BATCHES} receive batches with the dead-letter queue "
            "still not empty; something keeps dead-lettering messages",
            file=sys.stderr,
            flush=True,
        )
    if not redriven:
        print("no dead-lettered message found; run force_dlq_arrival.py first", flush=True)
        return 1
    exception_id, body = redriven[0]

    api_port = host_port("COLDLINE_API_HOST_PORT", 8000)
    with httpx.Client(base_url=f"http://localhost:{api_port}", timeout=5.0) as api:
        records = {redriven_id: _wait_for_terminal(api, redriven_id) for redriven_id, _ in redriven}
        record = records[exception_id]
        replay = None
        if record["state"] == "COMPLETED":
            # Deliver the same job once more, as a duplicate redrive or an
            # at-least-once redelivery would. An idempotent consumer
            # acknowledges it without changing the completed record.
            sqs.send_message(QueueUrl=main_url, MessageBody=body)
            consumed = _wait_for_empty(sqs, main_url)
            after = api.get(
                f"/api/v1/exceptions/{exception_id}", headers=bearer_headers("dispatcher-valid")
            ).json()
            replay = {
                "deliveries_after_completion": 1,
                "consumed": consumed,
                "state": after["state"],
                "updated_at_unchanged": after["updated_at"] == record["updated_at"],
                "summary_unchanged": after.get("summary") == record.get("summary"),
            }
    print(
        json.dumps(
            {
                "exception_id": exception_id,
                "state": record["state"],
                "summary": record.get("summary"),
                "replay": replay,
                "also_redriven": [redriven_id for redriven_id, _ in redriven[1:]],
                "missing": [
                    redriven_id
                    for redriven_id, _ in redriven
                    if records[redriven_id]["state"] == MISSING
                ],
            },
            indent=2,
        )
    )
    completed = all(
        each["state"] == "COMPLETED" for each in records.values() if each["state"] != MISSING
    )
    idempotent = replay is not None and (
        replay["consumed"]
        and replay["state"] == "COMPLETED"
        and replay["updated_at_unchanged"]
        and replay["summary_unchanged"]
    )
    return 0 if drained and completed and idempotent else 1


def _redrive_all(sqs: Any, dlq_url: str, main_url: str) -> tuple[list[tuple[str, str]], bool]:
    """Move every dead-lettered message back to the main queue, newest first.

    Returns each distinct exception identity with the body it was redriven
    with, ordered by the message's `SentTimestamp` from the newest to the
    oldest, and whether the queue was seen empty within `MAX_RECEIVE_BATCHES`
    receives. The first receive waits up to five seconds, as a single redrive
    always did; later receives only confirm that the queue is empty.
    """
    latest: dict[str, tuple[int, str]] = {}
    wait_seconds = 5
    drained = False
    for _ in range(MAX_RECEIVE_BATCHES):
        response = sqs.receive_message(
            QueueUrl=dlq_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=wait_seconds,
            AttributeNames=["SentTimestamp"],
        )
        messages = response.get("Messages") or []
        if not messages:
            drained = True
            break
        for message in messages:
            sqs.send_message(QueueUrl=main_url, MessageBody=message["Body"])
            sqs.delete_message(QueueUrl=dlq_url, ReceiptHandle=message["ReceiptHandle"])
            exception_id = json.loads(message["Body"])["exception_id"]
            sent_at = int(message.get("Attributes", {}).get("SentTimestamp", 0))
            if exception_id not in latest or sent_at >= latest[exception_id][0]:
                latest[exception_id] = (sent_at, message["Body"])
        wait_seconds = 1
    ordered = sorted(latest, key=lambda each: latest[each][0], reverse=True)
    return [(exception_id, latest[exception_id][1]) for exception_id in ordered], drained


def _wait_for_empty(sqs: Any, url: str) -> bool:
    """Poll until the main queue holds no visible or in-flight message."""
    for _ in range(30):
        counts = queue_counts(sqs, url)
        if not any(counts.values()):
            return True
        time.sleep(1)
    return False


def _wait_for_terminal(api: httpx.Client, exception_id: str) -> dict[str, object]:
    """Poll the durable record until it reaches a terminal state.

    A record the API does not have (404) is returned as `MISSING` at once:
    no amount of waiting will bring it back. The read is made as the dispatcher,
    which the summary endpoint requires from Task 4.2.
    """
    for _ in range(30):
        response = api.get(
            f"/api/v1/exceptions/{exception_id}", headers=bearer_headers("dispatcher-valid")
        )
        if response.status_code == 404:
            return {"state": MISSING}
        response.raise_for_status()
        record: dict[str, object] = response.json()
        if record["state"] in {"COMPLETED", "FAILED"}:
            return record
        time.sleep(1)
    raise TimeoutError(f"exception {exception_id} did not reach a terminal state")


if __name__ == "__main__":
    raise SystemExit(main())
