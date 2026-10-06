"""Coldline.

===================

File:              tests/failure/queue_client.py
Component:         Failure tools — Queue client
Purpose:           Connect the dead-letter exercise scripts to LocalStack SQS from the host.
Interacts With:    LocalStack SQS
Sprint/Task:       Sprint 3 — Project 3
Concepts:          Dead-letter redrive, deterministic infrastructure
Tools:             Python 3.12, boto3, LocalStack
"""

import time
from typing import Any

from adapters.queue import create_sqs_client
from tests.runtime_config import host_port

# Margin added to the queue's own visibility timeout while waiting for the first
# receive to return the just-published message. See `exhaust_receive_budget`.
FIRST_RECEIVE_MARGIN_SECONDS = 10.0


def client() -> Any:
    """Return one SQS client reaching LocalStack from the host, not a container."""
    port = host_port("COLDLINE_LOCALSTACK_HOST_PORT", 4566)
    return create_sqs_client(
        endpoint_url=f"http://localhost:{port}",
        region_name="us-east-1",
        access_key_id="localstack-development-key",
        secret_access_key="localstack-development-secret",
    )


def queue_url(sqs: Any, *, name: str) -> str:
    """Resolve one supplied queue name to its URL."""
    return str(sqs.get_queue_url(QueueName=name)["QueueUrl"])


def queue_counts(sqs: Any, url: str) -> dict[str, int]:
    """Return one queue's visible and in-flight message counts, read from SQS itself."""
    attributes = sqs.get_queue_attributes(
        QueueUrl=url,
        AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )["Attributes"]
    return {
        "approximate_number_of_messages": int(attributes["ApproximateNumberOfMessages"]),
        "approximate_number_of_messages_not_visible": int(
            attributes["ApproximateNumberOfMessagesNotVisible"]
        ),
    }


def exhaust_receive_budget(sqs: Any, url: str, *, max_receive_count: int) -> dict[str, Any]:
    """Receive one message without acknowledging it until SQS dead-letters it.

    One extra receive beyond the bound is what makes SQS redrive the message
    instead of returning it to the main queue once more, so an empty receive
    *after* the first message is the expected end of the loop.

    An empty receive *before* the first message is different: the message may
    be in flight to a receiver that no longer exists. A worker container that
    is killed during its own long poll leaves that request open inside
    LocalStack, which can hand the next published message to it; the message
    then stays invisible for one visibility timeout and returns with one
    receive already counted. So the first receive keeps polling until the
    queue's own visibility timeout plus a margin has passed, instead of giving
    up on the first empty answer.

    Returns the number of receives observed, how long the first one took, and
    the deadline the first receive was allowed: the fields of the timing line
    in `tests/failure/forcing_timing.py`.
    """
    visibility_timeout = int(
        sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["VisibilityTimeout"])["Attributes"][
            "VisibilityTimeout"
        ]
    )
    deadline_seconds = visibility_timeout + FIRST_RECEIVE_MARGIN_SECONDS
    started = time.monotonic()
    deadline = started + deadline_seconds
    first_receive_seconds: float | None = None
    announced_wait = False
    attempt = 0
    while attempt < max_receive_count + 1:
        response = sqs.receive_message(
            QueueUrl=url,
            MaxNumberOfMessages=1,
            WaitTimeSeconds=2,
            AttributeNames=["ApproximateReceiveCount"],
        )
        messages = response.get("Messages")
        if not messages:
            if attempt == 0 and time.monotonic() < deadline:
                if not announced_wait:
                    print(
                        "no message visible yet; polling for up to "
                        f"{deadline_seconds:.0f}s "
                        "(one visibility timeout plus a margin)",
                        flush=True,
                    )
                    announced_wait = True
                continue
            break
        attempt += 1
        if first_receive_seconds is None:
            first_receive_seconds = round(time.monotonic() - started, 1)
        receive_count = int(messages[0]["Attributes"]["ApproximateReceiveCount"])
        print(f"attempt {attempt}: receive_count={receive_count}, left unacknowledged", flush=True)
        sqs.change_message_visibility(
            QueueUrl=url,
            ReceiptHandle=messages[0]["ReceiptHandle"],
            VisibilityTimeout=0,
        )
    return {
        "receives_observed": attempt,
        "first_receive_seconds": first_receive_seconds,
        "deadline_seconds": deadline_seconds,
    }
