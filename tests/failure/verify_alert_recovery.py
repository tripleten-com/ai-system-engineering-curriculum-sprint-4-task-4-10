"""Coldline.

===================

File:              tests/failure/verify_alert_recovery.py
Component:         Failure tools — Verify alert recovery
Purpose:           Redrive the dead-lettered exercise messages and prove the alert resolves.
Interacts With:    The API, LocalStack SQS, Alertmanager
Sprint/Task:       Sprint 3 — Project 3
Concepts:          SLO/alert, dead-letter redrive, idempotent recovery, evidence
Tools:             Python 3.12, boto3, httpx
"""

import json
import time
from typing import Any

import httpx

from tests.failure.force_dlq_arrival import DEAD_LETTER_NAME, QUEUE_NAME
from tests.failure.queue_client import client, queue_url
from tests.failure.trigger_alert_load import wait_for_alert_state
from tests.runtime_config import host_port
from tests.security.fixtures import bearer_headers

# Long enough to clear a correctly configured alert's `resolve_timeout` plus
# scrape and evaluation slack.
RESOLVED_WAIT_SECONDS = 45.0


def main() -> int:
    """Redrive every dead-lettered message, then confirm recovery and alert resolution.

    Run this after `poe trigger-alert-load`, which restarts the worker; that
    is a precondition here, not something this script repeats. The redriven
    message is the *same* durable exception identity the load script
    submitted; `WorkerApplication` treats a delivery for an already-terminal
    identity as a safe replay, so this proves recovery is idempotent, not
    merely eventual.

    The dead-letter queue can hold more than that one message: a failed
    `poe slo-contract` or `poe trigger-alert-load` run leaves its own message
    behind. The alert watches the queue's whole depth, so it can only resolve
    once every message is gone, and this script redrives them all. It reports
    the most recently sent one, the message the load script just forced, as
    `exception_id`, and lists any older ones under `also_redriven`.
    """
    sqs = client()
    dlq_url = queue_url(sqs, name=DEAD_LETTER_NAME)
    main_url = queue_url(sqs, name=QUEUE_NAME)

    exception_ids = _redrive_all(sqs, dlq_url, main_url)
    if not exception_ids:
        print("no dead-lettered message found; run trigger_alert_load.py first", flush=True)
        return 1

    api_port = host_port("COLDLINE_API_HOST_PORT", 8000)
    with httpx.Client(base_url=f"http://localhost:{api_port}", timeout=5.0) as api:
        records = {
            exception_id: _wait_for_terminal(api, exception_id) for exception_id in exception_ids
        }

    alert_state, _ = wait_for_alert_state(
        target_state="resolved", timeout_seconds=RESOLVED_WAIT_SECONDS
    )
    resolved = alert_state in {"resolved", "absent"}
    completed = all(record["state"] == "COMPLETED" for record in records.values())

    newest = exception_ids[0]
    print(
        json.dumps(
            {
                "exception_id": newest,
                "state": records[newest]["state"],
                "alert_state": alert_state,
                "also_redriven": exception_ids[1:],
            },
            indent=2,
        )
    )
    return 0 if completed and resolved else 1


def _redrive_all(sqs: Any, dlq_url: str, main_url: str) -> list[str]:
    """Move every dead-lettered message back to the main queue, newest first.

    Returns the distinct exception identities, ordered by each message's
    `SentTimestamp` from the newest to the oldest. The first receive waits
    up to five seconds, as a single redrive always did; later receives only
    confirm that the queue is empty.
    """
    sent: dict[str, int] = {}
    wait_seconds = 5
    while True:
        response = sqs.receive_message(
            QueueUrl=dlq_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=wait_seconds,
            AttributeNames=["SentTimestamp"],
        )
        messages = response.get("Messages") or []
        if not messages:
            break
        for message in messages:
            sqs.send_message(QueueUrl=main_url, MessageBody=message["Body"])
            sqs.delete_message(QueueUrl=dlq_url, ReceiptHandle=message["ReceiptHandle"])
            exception_id = json.loads(message["Body"])["exception_id"]
            sent_at = int(message.get("Attributes", {}).get("SentTimestamp", 0))
            sent[exception_id] = max(sent_at, sent.get(exception_id, 0))
        wait_seconds = 1
    return sorted(sent, key=sent.__getitem__, reverse=True)


def _wait_for_terminal(api: httpx.Client, exception_id: str) -> dict[str, object]:
    """Poll the durable record, as the dispatcher, until it reaches a terminal state."""
    for _ in range(30):
        response = api.get(
            f"/api/v1/exceptions/{exception_id}", headers=bearer_headers("dispatcher-valid")
        )
        response.raise_for_status()
        record: dict[str, object] = response.json()
        if record["state"] in {"COMPLETED", "FAILED"}:
            return record
        time.sleep(1)
    raise TimeoutError(f"exception {exception_id} did not reach a terminal state")


if __name__ == "__main__":
    raise SystemExit(main())
