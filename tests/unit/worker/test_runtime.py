"""Coldline.

===================

File:              tests/unit/worker/test_runtime.py
Component:         Unit tests — Test Runtime
Purpose:           Tests for worker-loop resilience at transport boundaries.
Interacts With:    One isolated source responsibility
Sprint/Task:       Sprint 1 — Project 1
Concepts:          Fast feedback, failure paths, state invariants
Tools:             Python 3.12, pytest, OpenTelemetry
"""

import asyncio
from datetime import UTC, datetime

import pytest
from opentelemetry import trace

from domain.contracts import ExceptionJob, JobDelivery, SensorReading
from worker.runtime import run_loop
from worker.use_cases import ProcessingDisposition


def _delivery(message_id: str) -> JobDelivery:
    """Build one valid delivery for a runtime-loop test."""
    return JobDelivery(
        message_id=message_id,
        delivery_count=1,
        job=ExceptionJob(
            exception_id=f"exc-{message_id}",
            accepted_at=datetime.now(UTC),
            reading=SensorReading(
                reading_id=f"reading-{message_id}",
                shipment_id="SHP-TEST",
                temperature_c=9.0,
                allowed_min_c=2.0,
                allowed_max_c=8.0,
                recorded_at=datetime.now(UTC),
            ),
        ),
    )


class TwoDeliveryQueue:
    """Return two deliveries and record acknowledgement behavior."""

    def __init__(self) -> None:
        """Prepare two ordered deliveries."""
        self.deliveries = [_delivery("1-0"), _delivery("2-0")]
        self.acknowledged: list[str] = []

    async def claim_stale(self, *, minimum_idle_ms: int) -> JobDelivery | None:
        """Return no stale delivery in this focused test."""
        return None

    async def read(self, *, block_ms: int = 1000) -> JobDelivery | None:
        """Return the next delivery or yield while the test cancels the loop."""
        if self.deliveries:
            return self.deliveries.pop(0)
        await asyncio.sleep(60)
        return None

    async def acknowledge(self, message_id: str) -> None:
        """Record one terminal acknowledgement."""
        self.acknowledged.append(message_id)

    async def queue_depth(self) -> int:
        """Return a bounded diagnostic value."""
        return len(self.deliveries)

    async def pending_count(self) -> int:
        """Return a bounded diagnostic value."""
        return 0

    async def publish(self, job: ExceptionJob) -> str:
        """Satisfy the full JobQueue contract; publishing is unused here."""
        return "unused"


class FailThenSucceedApplication:
    """Raise once, then prove that the worker loop continued."""

    def __init__(self) -> None:
        """Create a completion signal and call counter."""
        self.calls = 0
        self.completed = asyncio.Event()

    async def process(self, job: ExceptionJob, *, delivery_count: int) -> ProcessingDisposition:
        """Raise for the first delivery and acknowledge the second."""
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("simulated repository driver error")
        self.completed.set()
        return ProcessingDisposition.ACK


class FailTransportOnceQueue(TwoDeliveryQueue):
    """Raise one transient Redis-like error before returning a delivery."""

    def __init__(self) -> None:
        """Prepare one transport failure and the inherited deliveries."""
        super().__init__()
        self.claim_calls = 0

    async def claim_stale(self, *, minimum_idle_ms: int) -> JobDelivery | None:
        """Fail the first transport call and recover on the next loop."""
        self.claim_calls += 1
        if self.claim_calls == 1:
            raise ConnectionError("redis connection reset")
        return None


class SucceedingApplication:
    """Signal when a delivery reaches the application after transport recovery."""

    def __init__(self) -> None:
        """Create a completion signal."""
        self.completed = asyncio.Event()

    async def process(self, job: ExceptionJob, *, delivery_count: int) -> ProcessingDisposition:
        """Acknowledge one delivery and signal the test."""
        self.completed.set()
        return ProcessingDisposition.ACK


@pytest.mark.asyncio
async def test_worker_loop_survives_one_unhandled_delivery_error() -> None:
    """One adapter failure must leave that job pending without killing the worker."""
    queue = TwoDeliveryQueue()
    application = FailThenSucceedApplication()
    loop = asyncio.create_task(
        run_loop(
            queue,
            application,  # type: ignore[arg-type] - focused boundary fake
            trace.get_tracer("test"),
            stale_message_ms=30_000,
            transport_error_backoff_seconds=0,
        )
    )

    await asyncio.wait_for(application.completed.wait(), timeout=1)
    loop.cancel()
    with pytest.raises(asyncio.CancelledError):
        await loop

    assert application.calls == 2
    assert queue.acknowledged == ["2-0"]


@pytest.mark.asyncio
async def test_worker_loop_survives_one_transport_error() -> None:
    """A transient queue read failure must not terminate the worker process."""
    queue = FailTransportOnceQueue()
    application = SucceedingApplication()
    loop = asyncio.create_task(
        run_loop(
            queue,
            application,  # type: ignore[arg-type] - focused boundary fake
            trace.get_tracer("test"),
            stale_message_ms=30_000,
            transport_error_backoff_seconds=0,
        )
    )

    await asyncio.wait_for(application.completed.wait(), timeout=2)
    loop.cancel()
    with pytest.raises(asyncio.CancelledError):
        await loop

    assert queue.claim_calls >= 2
    assert queue.acknowledged[0] == "1-0"
