"""Coldline.

===================

File:              src/ports/job_queue.py
Component:         Port — Job Queue
Purpose:           Define the provider-neutral asynchronous job-queue port.
Interacts With:    Use cases and provider adapters
Sprint/Task:       Sprint 1 — Project 1
Concepts:          Dependency inversion, provider-neutral interface
Tools:             Python 3.12
"""

from typing import Protocol, runtime_checkable

from domain.contracts import ExceptionJob, JobDelivery


@runtime_checkable
class JobQueue(Protocol):
    """Publish, recover, observe, and acknowledge exception jobs."""

    async def publish(self, job: ExceptionJob) -> str:
        """Publish one exception job and return its transport message ID."""
        ...

    async def read(self, *, block_ms: int = 1000) -> JobDelivery | None:
        """Receive one new delivery when work is available."""
        ...

    async def claim_stale(self, *, minimum_idle_ms: int) -> JobDelivery | None:
        """Recover one unacknowledged delivery after its stale threshold."""
        ...

    async def acknowledge(self, message_id: str) -> None:
        """Acknowledge one message after terminal persistence."""
        ...

    async def queue_depth(self) -> int:
        """Return a bounded queue-depth diagnostic."""
        ...

    async def pending_count(self) -> int:
        """Return the count of delivered but unacknowledged jobs."""
        ...
