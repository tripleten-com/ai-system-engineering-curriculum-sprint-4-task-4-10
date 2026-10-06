"""Coldline.

===================

File:              src/api/use_cases.py
Component:         API — Use Cases
Purpose:           Coordinate exception ingestion without provider-specific dependencies.
Interacts With:    FastAPI, domain, ports, and adapters
Sprint/Task:       Sprint 1 — Project 1
Concepts:          HTTP boundary, composition, asynchronous work
Tools:             Python 3.12
"""

from collections.abc import Callable
from datetime import datetime

from domain import exception_id_for, requires_exception
from domain.contracts import ExceptionJob, ExceptionRecord, ExceptionState, SensorReading
from domain.redaction import redact_sensor_reading
from domain.repositories import ExceptionRepository, StateConflict
from ports import JobQueue


class InRangeReading(ValueError):
    """Report that a reading does not require exception work."""


class QueueUnavailable(RuntimeError):
    """Report that accepted exception work could not be published."""


class TerminalExceptionConflict(RuntimeError):
    """Report that an idempotent identity already has a terminal failure."""


class ReadingApplication:
    """Persist and enqueue one validated sensor exception."""

    def __init__(
        self,
        repository: ExceptionRepository,
        queue: JobQueue,
        *,
        clock: Callable[[], datetime],
    ) -> None:
        """Receive provider-neutral collaborators through explicit composition."""
        self._repository = repository
        self._queue = queue
        self._clock = clock

    async def accept(self, reading: SensorReading) -> ExceptionRecord:
        """Accept one out-of-range reading and schedule background work.

        The order is deliberate:

        1. Remove supplied PII before storage, logs, or provider use.
        2. Derive the stable identity and reuse an existing workflow.
        3. Persist ``QUEUED`` before making the message visible.
        4. Publish exactly one job for the durable identity.

        A retry returns the existing record. A publication failure becomes a
        visible terminal state because silently losing accepted work is unsafe.
        """
        reading = redact_sensor_reading(reading)
        if not requires_exception(reading):
            raise InRangeReading("reading is within its accepted handling range")

        exception_id = exception_id_for(reading)
        existing = await self._repository.get(exception_id)
        if existing is not None and existing.state is ExceptionState.FAILED:
            raise TerminalExceptionConflict(f"exception {exception_id} is already terminal FAILED")
        if existing is not None and existing.state is not ExceptionState.RECEIVED:
            return existing

        accepted_at = self._clock()
        if existing is None:
            record = await self._repository.create(
                ExceptionRecord(
                    exception_id=exception_id,
                    reading=reading,
                    state=ExceptionState.RECEIVED,
                    accepted_at=accepted_at,
                    updated_at=accepted_at,
                )
            )
        else:
            record = existing
        if record.state is not ExceptionState.RECEIVED:
            return record

        # The worker must never observe work before the durable record says QUEUED.
        try:
            queued = await self._repository.transition(
                exception_id,
                {ExceptionState.RECEIVED},
                ExceptionState.QUEUED,
            )
        except StateConflict:
            concurrent = await self._repository.get(exception_id)
            if concurrent is None:
                raise
            if concurrent.state is ExceptionState.FAILED:
                raise TerminalExceptionConflict(
                    f"exception {exception_id} is already terminal FAILED"
                ) from None
            return concurrent

        # Publishing is the only external side effect owned by this use case.
        try:
            await self._queue.publish(
                ExceptionJob(
                    exception_id=exception_id,
                    reading=reading,
                    accepted_at=accepted_at,
                )
            )
        except Exception as exc:
            await self._repository.transition(
                exception_id,
                {ExceptionState.QUEUED},
                ExceptionState.FAILED,
                failure_reason="job_queue_unavailable",
            )
            raise QueueUnavailable("job queue is unavailable") from exc

        return queued
