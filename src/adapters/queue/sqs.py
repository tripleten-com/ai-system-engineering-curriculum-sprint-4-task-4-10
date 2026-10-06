"""Coldline.

===================

File:              src/adapters/queue/sqs.py
Component:         Adapter — SQS
Purpose:           Implement the supplied LocalStack SQS/DLQ JobQueue adapter.
Interacts With:    LocalStack SQS in development, domain contracts, ports
Sprint/Task:       Sprint 3 — Project 3
Concepts:          Boundary translation, provider isolation, dead-letter redrive
Tools:             Python 3.12, boto3, LocalStack
"""

import asyncio
import json
from typing import Any

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError, EndpointConnectionError
from opentelemetry import trace
from opentelemetry.propagate import inject

from domain.contracts import ExceptionJob, JobDelivery

_TRACER = trace.get_tracer(__name__)
_CARRIER_KEYS = ("traceparent", "tracestate")


def create_sqs_client(
    *,
    endpoint_url: str,
    region_name: str,
    access_key_id: str,
    secret_access_key: str,
) -> Any:
    """Create one SQS-compatible client for a composition root.

    Only a composition root calls this. Application code receives the
    ``JobQueue`` port and never sees a client, an endpoint, or a credential.
    """
    return boto3.client(
        "sqs",
        endpoint_url=endpoint_url,
        region_name=region_name,
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
        config=Config(retries={"max_attempts": 3, "mode": "standard"}),
    )


def _get_or_create_queue_url(client: Any, name: str) -> str:
    """Return one queue's URL, creating it with no fixed attributes if absent.

    ``create_queue`` is not idempotent across attribute changes: SQS (and
    LocalStack) reject it outright if a queue by that name already exists
    with *different* attributes, rather than returning the existing queue.
    Creating with no attributes here, then converging on the desired ones
    through ``set_queue_attributes`` — which is a true idempotent update —
    is what makes a repeated run (restart, Codespaces resume, or a changed
    policy) converge instead of failing outright.
    """
    try:
        return str(client.create_queue(QueueName=name)["QueueUrl"])
    except client.exceptions.QueueNameExists:
        return str(client.get_queue_url(QueueName=name)["QueueUrl"])


async def ensure_queue_when_ready(
    client: Any,
    *,
    queue_name: str,
    dead_letter_name: str,
    visibility_timeout_seconds: int,
    max_receive_count: int,
    endpoint: str,
    attempts: int = 30,
    delay_seconds: float = 2.0,
) -> tuple[str, str]:
    """Retry the full provisioning call until the queue service answers.

    Mirrors ``ObjectStore``'s own "not yet reachable" retry shape: a composition
    root awaits this instead of catching a cloud SDK exception type itself, so
    ``botocore`` stays an adapter-only import. Retrying the whole provisioning
    call, not only an initial probe, also absorbs a transient failure on
    ``create_queue``/``set_queue_attributes`` after the service first answers,
    not only a service that has not started listening yet.
    """
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            return await asyncio.to_thread(
                ensure_queue,
                client,
                queue_name=queue_name,
                dead_letter_name=dead_letter_name,
                visibility_timeout_seconds=visibility_timeout_seconds,
                max_receive_count=max_receive_count,
            )
        except (ClientError, EndpointConnectionError) as exc:
            last_error = exc
            if attempt + 1 < attempts:
                await asyncio.sleep(delay_seconds)
    raise RuntimeError(
        f"the queue service at {endpoint} did not answer after {attempts} attempts; "
        "start the stack with the localstack Compose profile enabled (`poe start`)"
    ) from last_error


def ensure_queue(
    client: Any,
    *,
    queue_name: str,
    dead_letter_name: str,
    visibility_timeout_seconds: int,
    max_receive_count: int,
) -> tuple[str, str]:
    """Create the main queue and its dead-letter queue, and bind a redrive policy.

    Idempotent: a repeated call, including one that changes the requested
    visibility timeout or receive-count bound, converges the existing queues
    on the new policy rather than failing. Called once, from the composition
    root, before any adapter reads or publishes. Not part of the ``JobQueue``
    port: queue *provisioning* is a deployment concern, not a per-message one.
    """
    dlq_url = _get_or_create_queue_url(client, dead_letter_name)
    dlq_arn = client.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    redrive_policy = json.dumps(
        {"deadLetterTargetArn": dlq_arn, "maxReceiveCount": max_receive_count}
    )
    queue_url = _get_or_create_queue_url(client, queue_name)
    client.set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={
            "VisibilityTimeout": str(visibility_timeout_seconds),
            "RedrivePolicy": redrive_policy,
        },
    )
    return queue_url, dlq_url


def encode_job(job: ExceptionJob) -> str:
    """Serialize one canonical job for SQS message body storage."""
    return job.model_dump_json()


def decode_job(payload: str) -> ExceptionJob:
    """Deserialize one canonical job from an SQS message body."""
    return ExceptionJob.model_validate_json(payload)


class SqsJobQueue:
    """Translate the provider-neutral ``JobQueue`` contract to LocalStack SQS.

    SQS carries staleness recovery inside the transport itself: a message an
    earlier receiver never deleted becomes visible to any receiver again once
    its visibility timeout elapses, and SQS moves it to the bound dead-letter
    queue automatically once ``ApproximateReceiveCount`` passes the queue's own
    ``maxReceiveCount``. Neither behavior needs code here; ``claim_stale``
    exists only to satisfy the shared port, and delegates to the same receive
    call ``read`` uses.

    The returned ``JobDelivery.message_id`` is the SQS *receipt handle*, not
    the message ID: only the handle from the *current* receive can delete the
    message, and that is exactly what ``acknowledge`` needs.
    """

    def __init__(
        self,
        client: Any,
        *,
        queue_url: str,
        wait_time_seconds: int = 5,
    ) -> None:
        """Bind the adapter to one protected queue URL and long-poll window."""
        if not 0 <= wait_time_seconds <= 20:
            raise ValueError("wait_time_seconds must be an SQS-valid long-poll window (0-20)")
        self._client = client
        self._queue_url = queue_url
        self._wait_time_seconds = wait_time_seconds

    async def initialize(self) -> None:
        """No-op: queue and dead-letter provisioning happens once, at startup."""

    async def publish(self, job: ExceptionJob) -> str:
        """Publish one job, carrying trace context in a message attribute."""
        with _TRACER.start_as_current_span(
            "job_queue.publish",
            attributes={"coldline.exception_id": job.exception_id},
        ):
            carrier: dict[str, str] = {}
            inject(carrier)
            attributes = {
                key: {"DataType": "String", "StringValue": value} for key, value in carrier.items()
            }
            response = await asyncio.to_thread(
                self._client.send_message,
                QueueUrl=self._queue_url,
                MessageBody=encode_job(job),
                MessageAttributes=attributes,
            )
        return str(response["MessageId"])

    async def read(self, *, block_ms: int = 1000) -> JobDelivery | None:
        """Long-poll for at most one delivery within the bounded wait.

        SQS's own ``WaitTimeSeconds`` is capped at 20 seconds and given in
        whole seconds; ``block_ms`` is rounded up and clamped to that range.
        """
        wait_seconds = min(20, max(0, (block_ms + 999) // 1000))
        response = await asyncio.to_thread(
            self._client.receive_message,
            QueueUrl=self._queue_url,
            MaxNumberOfMessages=1,
            WaitTimeSeconds=wait_seconds,
            AttributeNames=["ApproximateReceiveCount"],
            MessageAttributeNames=list(_CARRIER_KEYS),
        )
        messages = response.get("Messages")
        if not messages:
            return None
        return self._to_delivery(messages[0])

    async def claim_stale(self, *, minimum_idle_ms: int) -> JobDelivery | None:
        """Recover one delivery SQS has already made visible again.

        SQS applies ``minimum_idle_ms`` itself, as the queue's own visibility
        timeout; this receives whatever the transport currently has to offer.
        """
        return await self.read(block_ms=0)

    async def acknowledge(self, message_id: str) -> None:
        """Delete one message using the receipt handle received with it."""
        await asyncio.to_thread(
            self._client.delete_message,
            QueueUrl=self._queue_url,
            ReceiptHandle=message_id,
        )

    async def queue_depth(self) -> int:
        """Return the approximate number of messages available to receive."""
        return await self._attribute("ApproximateNumberOfMessages")

    async def pending_count(self) -> int:
        """Return the approximate number of messages currently in flight."""
        return await self._attribute("ApproximateNumberOfMessagesNotVisible")

    async def _attribute(self, name: str) -> int:
        response = await asyncio.to_thread(
            self._client.get_queue_attributes,
            QueueUrl=self._queue_url,
            AttributeNames=[name],
        )
        return int(response["Attributes"][name])

    def _to_delivery(self, message: dict[str, Any]) -> JobDelivery:
        carrier = {
            key: message["MessageAttributes"][key]["StringValue"]
            for key in _CARRIER_KEYS
            if key in message.get("MessageAttributes", {})
        }
        return JobDelivery(
            message_id=message["ReceiptHandle"],
            job=decode_job(message["Body"]),
            delivery_count=int(message["Attributes"]["ApproximateReceiveCount"]),
            trace_carrier=carrier,
        )


__all__ = [
    "SqsJobQueue",
    "create_sqs_client",
    "ensure_queue",
    "ensure_queue_when_ready",
    "encode_job",
    "decode_job",
]
