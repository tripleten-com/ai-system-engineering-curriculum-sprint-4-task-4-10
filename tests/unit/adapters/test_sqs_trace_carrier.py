"""Coldline.

===================

File:              tests/unit/adapters/test_sqs_trace_carrier.py
Component:         Unit tests — SQS trace carrier
Purpose:           Prove the queue adapter carries the API's trace to the worker's span.
Interacts With:    src/adapters/queue/sqs.py, src/worker/runtime.py, OpenTelemetry SDK
Sprint/Task:       Sprint 4 — Project 4
Concepts:          Trace continuity across an asynchronous boundary, W3C trace context
Tools:             Python 3.12, pytest, OpenTelemetry

The API and the worker are two processes. The only thing that can join their
spans into one trace is what the message carries: the queue adapter injects
the W3C ``traceparent`` into an SQS message attribute on publish and hands it
back as the delivery's ``trace_carrier``, and the worker loop starts its span
from that carrier. This module proves both halves with an in-memory exporter
and a fake SQS client, so the joined trace `poe scenario` reports is not an
accident of one run.
"""

import asyncio
from datetime import UTC, datetime
from typing import Any

import pytest
from opentelemetry import trace
from opentelemetry.propagate import extract
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from adapters.queue import SqsJobQueue
from domain.contracts import ExceptionJob, JobDelivery, SensorReading
from worker.runtime import run_loop
from worker.use_cases import ProcessingDisposition

EXPORTER = InMemorySpanExporter()


def _provider() -> TracerProvider:
    """Return the one SDK tracer provider this process exports through.

    The adapters capture the global tracer at import, so the provider has to
    be the global one; the API allows it to be set once per process, which is
    what this module-level installation does. Every other unit test keeps
    working with a recording provider in place.
    """
    current = trace.get_tracer_provider()
    if isinstance(current, TracerProvider):
        return current
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(EXPORTER))
    trace.set_tracer_provider(provider)
    installed = trace.get_tracer_provider()
    assert isinstance(installed, TracerProvider)
    return installed


class FakeSqsClient:
    """Hold published messages in memory and hand them back on receive."""

    def __init__(self) -> None:
        """Start with an empty queue."""
        self.messages: list[dict[str, Any]] = []

    def send_message(
        self, *, QueueUrl: str, MessageBody: str, MessageAttributes: dict[str, Any]
    ) -> dict[str, str]:
        """Store the body and its attributes exactly as SQS would."""
        self.messages.append(
            {
                "MessageId": f"message-{len(self.messages) + 1}",
                "ReceiptHandle": f"receipt-{len(self.messages) + 1}",
                "Body": MessageBody,
                "MessageAttributes": MessageAttributes,
                "Attributes": {"ApproximateReceiveCount": "1"},
            }
        )
        return {"MessageId": self.messages[-1]["MessageId"]}

    def receive_message(self, **_: Any) -> dict[str, Any]:
        """Hand back the oldest stored message, or nothing."""
        if not self.messages:
            return {}
        return {"Messages": [self.messages.pop(0)]}

    def delete_message(self, **_: Any) -> None:
        """Accept an acknowledgement."""

    def get_queue_attributes(self, **_: Any) -> dict[str, Any]:
        """Report an empty queue."""
        return {
            "Attributes": {
                "ApproximateNumberOfMessages": "0",
                "ApproximateNumberOfMessagesNotVisible": "0",
            }
        }


def _job() -> ExceptionJob:
    """Return one job with a handling note, as the API publishes it."""
    now = datetime.now(UTC)
    return ExceptionJob(
        exception_id="exc-carrier-001",
        accepted_at=now,
        reading=SensorReading(
            reading_id="reading-carrier-001",
            shipment_id="shipment-carrier-001",
            temperature_c=9.2,
            allowed_min_c=2.0,
            allowed_max_c=8.0,
            recorded_at=now,
            handling_note="carried as written",
        ),
    )


class OneDeliveryQueue:
    """Serve one prepared delivery, then wait until the test cancels the loop."""

    def __init__(self, delivery: JobDelivery) -> None:
        """Hold the delivery to serve once."""
        self.deliveries = [delivery]
        self.acknowledged: list[str] = []

    async def claim_stale(self, *, minimum_idle_ms: int) -> JobDelivery | None:
        """Return no stale delivery."""
        return None

    async def read(self, *, block_ms: int = 1000) -> JobDelivery | None:
        """Return the delivery once, then park."""
        if self.deliveries:
            return self.deliveries.pop(0)
        await asyncio.sleep(60)
        return None

    async def acknowledge(self, message_id: str) -> None:
        """Record the acknowledgement."""
        self.acknowledged.append(message_id)

    async def queue_depth(self) -> int:
        """Return a bounded diagnostic value."""
        return 0

    async def pending_count(self) -> int:
        """Return a bounded diagnostic value."""
        return 0

    async def publish(self, job: ExceptionJob) -> str:
        """Satisfy the port; unused here."""
        return "unused"


class RecordingApplication:
    """Capture the trace id the worker span runs under, then acknowledge."""

    def __init__(self) -> None:
        """Prepare the completion signal."""
        self.trace_id: int | None = None
        self.completed = asyncio.Event()

    async def process(self, job: ExceptionJob, *, delivery_count: int) -> ProcessingDisposition:
        """Read the current span's trace id and signal the test."""
        self.trace_id = trace.get_current_span().get_span_context().trace_id
        self.completed.set()
        return ProcessingDisposition.ACK


@pytest.mark.asyncio
async def test_publish_injects_the_current_trace_into_the_message_attributes() -> None:
    """The message leaves the API carrying the publishing span's trace context."""
    tracer = _provider().get_tracer("test_sqs_trace_carrier")
    client = FakeSqsClient()
    queue = SqsJobQueue(client, queue_url="https://queue.invalid/main")

    with tracer.start_as_current_span("POST /api/v1/readings") as api_span:
        api_trace_id = api_span.get_span_context().trace_id
        await queue.publish(_job())

    attributes = client.messages[0]["MessageAttributes"]
    assert "traceparent" in attributes
    traceparent = attributes["traceparent"]["StringValue"]
    assert traceparent.split("-")[1] == format(api_trace_id, "032x")


@pytest.mark.asyncio
async def test_read_returns_the_carrier_and_the_job_with_its_note() -> None:
    """The delivery hands the worker the same carrier and the raw handling note."""
    tracer = _provider().get_tracer("test_sqs_trace_carrier")
    client = FakeSqsClient()
    queue = SqsJobQueue(client, queue_url="https://queue.invalid/main")
    job = _job()
    with tracer.start_as_current_span("POST /api/v1/readings") as api_span:
        api_trace_id = api_span.get_span_context().trace_id
        await queue.publish(job)

    delivery = await queue.read(block_ms=0)

    assert delivery is not None
    assert delivery.job == job
    assert delivery.job.reading.handling_note == "carried as written"
    extracted = trace.get_current_span(extract(delivery.trace_carrier)).get_span_context()
    assert extracted.trace_id == api_trace_id


@pytest.mark.asyncio
async def test_worker_loop_continues_the_api_trace_from_the_carrier() -> None:
    """The worker's processing span is a child in the API's trace, not a new root."""
    tracer = _provider().get_tracer("test_sqs_trace_carrier")
    client = FakeSqsClient()
    publisher = SqsJobQueue(client, queue_url="https://queue.invalid/main")
    with tracer.start_as_current_span("POST /api/v1/readings") as api_span:
        api_trace_id = api_span.get_span_context().trace_id
        await publisher.publish(_job())
    delivery = await publisher.read(block_ms=0)
    assert delivery is not None
    application = RecordingApplication()
    queue = OneDeliveryQueue(delivery)
    loop = asyncio.create_task(
        run_loop(
            queue,
            application,  # type: ignore[arg-type] - focused boundary fake
            tracer,
            stale_message_ms=30_000,
            transport_error_backoff_seconds=0,
        )
    )

    await asyncio.wait_for(application.completed.wait(), timeout=2)
    loop.cancel()
    with pytest.raises(asyncio.CancelledError):
        await loop

    assert application.trace_id == api_trace_id
    assert queue.acknowledged == [delivery.message_id]
