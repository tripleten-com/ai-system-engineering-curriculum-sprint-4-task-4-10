"""Coldline.

===================

File:              tests/unit/api/test_use_cases.py
Component:         Unit tests — Test Use Cases
Purpose:           Unit tests for exception-ingress application behavior.
Interacts With:    One isolated source responsibility
Sprint/Task:       Sprint 4 — Project 4
Concepts:          Fast feedback, failure paths, state invariants
Tools:             Python 3.12, pytest
"""

from datetime import UTC, datetime

import pytest

from api.use_cases import (
    QueueUnavailable,
    ReadingApplication,
    TerminalExceptionConflict,
)
from domain.contracts import ExceptionJob, ExceptionRecord, ExceptionState, SensorReading
from domain.repositories import StateConflict


class MemoryRepository:
    """Store one exception record for application tests."""

    def __init__(self) -> None:
        """Initialize empty test state."""
        self.records: dict[str, ExceptionRecord] = {}

    async def get(self, exception_id: str) -> ExceptionRecord | None:
        """Return a stored exception."""
        return self.records.get(exception_id)

    async def create(self, record: ExceptionRecord) -> ExceptionRecord:
        """Create or return one exception."""
        return self.records.setdefault(record.exception_id, record)

    async def transition(
        self,
        exception_id: str,
        expected: set[ExceptionState],
        target: ExceptionState,
        *,
        summary: str | None = None,
        failure_reason: str | None = None,
    ) -> ExceptionRecord:
        """Apply a state transition for the test record."""
        current = self.records[exception_id]
        assert current.state in expected
        updated = current.model_copy(
            update={
                "state": target,
                "summary": summary if summary is not None else current.summary,
                "failure_reason": failure_reason,
                "updated_at": NOW,
            }
        )
        self.records[exception_id] = updated
        return updated


class RecordingQueue:
    """Record published jobs or simulate queue failure."""

    def __init__(self, *, fail: bool = False) -> None:
        """Configure a recording or failing queue."""
        self.fail = fail
        self.jobs: list[object] = []

    async def publish(self, job: object) -> str:
        """Record one job and return a synthetic message ID."""
        if self.fail:
            raise ConnectionError("queue unavailable")
        self.jobs.append(job)
        return "1-0"


class StateCheckingQueue:
    """Observe durable state at the exact queue-publication boundary."""

    def __init__(self, repository: MemoryRepository) -> None:
        """Keep the repository used by the application."""
        self.repository = repository
        self.state_at_publish: ExceptionState | None = None

    async def publish(self, job: ExceptionJob) -> str:
        """Record the state visible to a concurrently consuming worker."""
        self.state_at_publish = self.repository.records[job.exception_id].state
        return "1-0"


class ConcurrentWinnerRepository(MemoryRepository):
    """Simulate another request winning the RECEIVED-to-QUEUED transition."""

    async def transition(
        self,
        exception_id: str,
        expected: set[ExceptionState],
        target: ExceptionState,
        *,
        summary: str | None = None,
        failure_reason: str | None = None,
    ) -> ExceptionRecord:
        """Persist the concurrent winner and report the compare-and-set conflict."""
        if target is ExceptionState.QUEUED:
            current = self.records[exception_id]
            self.records[exception_id] = current.model_copy(update={"state": target})
            raise StateConflict("concurrent winner")
        return await super().transition(
            exception_id,
            expected,
            target,
            summary=summary,
            failure_reason=failure_reason,
        )


NOW = datetime(2026, 8, 28, tzinfo=UTC)
READING = SensorReading(
    reading_id="reading-syn-001",
    shipment_id="shipment-syn-001",
    temperature_c=9.2,
    allowed_min_c=2.0,
    allowed_max_c=8.0,
    recorded_at=NOW,
)


@pytest.mark.asyncio
async def test_accepting_exception_persists_and_publishes_one_job() -> None:
    """An excursion must become one queued durable exception."""
    repository = MemoryRepository()
    queue = RecordingQueue()
    application = ReadingApplication(repository, queue, clock=lambda: NOW)

    record = await application.accept(READING)

    assert record.state is ExceptionState.QUEUED
    assert len(queue.jobs) == 1


@pytest.mark.asyncio
async def test_record_is_queued_before_message_becomes_visible() -> None:
    """A fast worker must never observe a published job while its record is RECEIVED."""
    repository = MemoryRepository()
    queue = StateCheckingQueue(repository)
    application = ReadingApplication(repository, queue, clock=lambda: NOW)

    await application.accept(READING)

    assert queue.state_at_publish is ExceptionState.QUEUED


@pytest.mark.asyncio
async def test_concurrent_duplicate_returns_the_winning_durable_state() -> None:
    """A losing duplicate must not fail or publish a second message."""
    repository = ConcurrentWinnerRepository()
    queue = RecordingQueue()
    application = ReadingApplication(repository, queue, clock=lambda: NOW)

    record = await application.accept(READING)

    assert record.state is ExceptionState.QUEUED
    assert queue.jobs == []


@pytest.mark.asyncio
async def test_sensitive_context_is_redacted_before_persistence_and_publication() -> None:
    """Personal-looking context must not cross either durable boundary."""
    repository = MemoryRepository()
    queue = RecordingQueue()
    application = ReadingApplication(repository, queue, clock=lambda: NOW)
    reading = READING.model_copy(
        update={"context": "carrier note email=ada@example.test phone=+1 555 0100"}
    )

    record = await application.accept(reading)

    assert record.reading.context == "carrier note email=[REDACTED] phone=[REDACTED]"
    published = queue.jobs[0]
    assert isinstance(published, ExceptionJob)
    assert published.reading.context == record.reading.context


@pytest.mark.asyncio
async def test_handling_note_reaches_the_record_and_the_queue_as_written() -> None:
    """The note crosses both durable boundaries raw: nothing on the ingest path reads it.

    This pins the opening checkpoint's behavior so a later control is a
    visible change, not a desired state of this checkpoint.
    """
    repository = MemoryRepository()
    queue = RecordingQueue()
    application = ReadingApplication(repository, queue, clock=lambda: NOW)
    note = "Call Priya Natarajan on +1 555 0142 or priya.natarajan@example.test."
    reading = READING.model_copy(update={"handling_note": note})

    record = await application.accept(reading)

    assert record.reading.handling_note == note
    published = queue.jobs[0]
    assert isinstance(published, ExceptionJob)
    assert published.reading.handling_note == note


@pytest.mark.asyncio
async def test_duplicate_reading_does_not_publish_completed_work_again() -> None:
    """A completed duplicate must return the existing record without a side effect."""
    repository = MemoryRepository()
    queue = RecordingQueue()
    application = ReadingApplication(repository, queue, clock=lambda: NOW)
    first = await application.accept(READING)
    await repository.transition(
        first.exception_id,
        {ExceptionState.QUEUED},
        ExceptionState.COMPLETED,
        summary="done",
    )

    duplicate = await application.accept(READING)

    assert duplicate.state is ExceptionState.COMPLETED
    assert len(queue.jobs) == 1


@pytest.mark.asyncio
async def test_received_record_is_recovered_by_a_duplicate_submission() -> None:
    """A duplicate must resume work stranded before queue publication."""
    repository = MemoryRepository()
    exception_id = "exc-e6a7451a-fe1a-53ca-b280-9bf67f555977"
    repository.records[exception_id] = ExceptionRecord(
        exception_id=exception_id,
        reading=READING,
        state=ExceptionState.RECEIVED,
        accepted_at=NOW,
        updated_at=NOW,
    )
    queue = RecordingQueue()
    application = ReadingApplication(repository, queue, clock=lambda: NOW)

    recovered = await application.accept(READING)

    assert recovered.state is ExceptionState.QUEUED
    assert len(queue.jobs) == 1


@pytest.mark.asyncio
async def test_queue_failure_is_visible_and_terminal() -> None:
    """A publish failure must not leave accepted work silently pending."""
    repository = MemoryRepository()
    application = ReadingApplication(repository, RecordingQueue(fail=True), clock=lambda: NOW)

    with pytest.raises(QueueUnavailable):
        await application.accept(READING)

    record = next(iter(repository.records.values()))
    assert record.state is ExceptionState.FAILED
    assert record.failure_reason == "job_queue_unavailable"


@pytest.mark.asyncio
async def test_failed_duplicate_is_reported_without_requeue() -> None:
    """A terminal failed identity must not be misreported as newly accepted work."""
    repository = MemoryRepository()
    exception_id = "exc-e6a7451a-fe1a-53ca-b280-9bf67f555977"
    repository.records[exception_id] = ExceptionRecord(
        exception_id=exception_id,
        reading=READING,
        state=ExceptionState.FAILED,
        accepted_at=NOW,
        updated_at=NOW,
        failure_reason="job_queue_unavailable",
    )
    queue = RecordingQueue()
    application = ReadingApplication(repository, queue, clock=lambda: NOW)

    with pytest.raises(TerminalExceptionConflict, match="terminal FAILED"):
        await application.accept(READING)

    assert queue.jobs == []
