"""Coldline.

===================

File:              tests/unit/worker/test_use_cases.py
Component:         Unit tests — Test Use Cases
Purpose:           Unit tests for the worker paths Task 4.4 leaves as they are: replays, missing
                    records, retries, exhaustion, terminal failures, and the model request.
Interacts With:    One isolated source responsibility
Sprint/Task:       Sprint 4 — Project 4 / Task 4.4
Concepts:          Fast feedback, failure paths, state invariants, retrieval-augmented requests
Tools:             Python 3.12, pytest

``src/worker/use_cases.py`` is student-editable in Task 4.4, so nothing here pins what the
worker does to the handling note or the answer: that is the assessed rows' job, and a fresh
starter is expected to fail them. The note these tests use holds no personal detail, so
the supplied redactor leaves it as it is, and every test in this file holds on the starter
and on a correct completion alike.
"""

import json
import logging
from collections.abc import Mapping
from datetime import UTC, datetime

import pytest

from common.audit import AuditEvent, AuditRecord
from domain.contracts import (
    ExceptionJob,
    ExceptionRecord,
    ExceptionState,
    ModelAnswer,
    ModelRequest,
    SensorReading,
)
from domain.errors import TerminalProviderError
from domain.failures import RetrievalUnavailable
from worker.procedures import ProcedureExcerpt
from worker.use_cases import FINISHED_STATES, ProcessingDisposition, WorkerApplication


class MemoryRepository:
    """Store one exception record for worker tests."""

    def __init__(self, record: ExceptionRecord) -> None:
        """Initialize the repository with one durable record."""
        self.record = record

    async def get(self, exception_id: str) -> ExceptionRecord | None:
        """Return the record when identities match."""
        return self.record if exception_id == self.record.exception_id else None

    async def create(self, record: ExceptionRecord) -> ExceptionRecord:
        """Reject unexpected creation in worker tests."""
        raise AssertionError("worker must not create exception records")

    async def transition(
        self,
        exception_id: str,
        expected: set[ExceptionState],
        target: ExceptionState,
        *,
        summary: str | None = None,
        failure_reason: str | None = None,
        handling_class: str | None = None,
        next_step: str | None = None,
        rejection_reason: str | None = None,
    ) -> ExceptionRecord:
        """Apply one state transition."""
        assert self.record.state in expected
        self.record = self.record.model_copy(
            update={
                "state": target,
                "summary": summary if summary is not None else self.record.summary,
                "failure_reason": failure_reason,
                "handling_class": handling_class or self.record.handling_class,
                "next_step": next_step or self.record.next_step,
                "rejection_reason": rejection_reason or self.record.rejection_reason,
                "updated_at": NOW,
            }
        )
        return self.record


class RecordingAudit:
    """Keep every audit event the worker records, in order."""

    def __init__(self) -> None:
        """Start empty."""
        self.events: list[AuditRecord] = []

    async def record(
        self,
        event: AuditEvent | str,
        *,
        exception_id: str,
        details: Mapping[str, object] | None = None,
    ) -> AuditRecord:
        """Record one event."""
        stored = AuditRecord(str(event), exception_id, None, NOW, dict(details or {}))
        self.events.append(stored)
        return stored


class RecordingProvider:
    """Return a fixed raw answer or raise a fixed error, recording each request."""

    def __init__(self, *, fail: bool = False, text: str | None = None) -> None:
        """Configure a recording or failing provider with an optional raw answer."""
        self.fail = fail
        self.calls = 0
        self.requests: list[ModelRequest] = []
        self.text = text if text is not None else VALID_ANSWER

    async def summarize(self, request: ModelRequest) -> ModelAnswer:
        """Record one provider call."""
        self.calls += 1
        self.requests.append(request)
        if self.fail:
            raise TimeoutError("provider timeout")
        return ModelAnswer(provider="deterministic-local", text=self.text)


class TerminalRecordingProvider:
    """Raise a pre-classified terminal failure, as a bounded resilience wrapper would."""

    def __init__(self) -> None:
        """Track how many times the worker called the provider."""
        self.calls = 0

    async def summarize(self, request: ModelRequest) -> ModelAnswer:
        """Record one call and raise a terminal, non-retryable failure."""
        self.calls += 1
        raise TerminalProviderError("request rejected as permanently invalid")


class StaticProcedures:
    """Return one fixed excerpt, or fail the way an unreachable corpus store does."""

    def __init__(self, *, fail: bool = False) -> None:
        """Configure a fixed or failing lookup."""
        self.fail = fail
        self.readings: list[SensorReading] = []

    async def find(self, reading: SensorReading) -> ProcedureExcerpt:
        """Record the reading and answer with the fixed excerpt."""
        self.readings.append(reading)
        if self.fail:
            raise RetrievalUnavailable("retrieval backend is unreachable")
        return EXCERPT


NOW = datetime(2026, 8, 28, tzinfo=UTC)
# A note with no personal detail: the supplied redactor returns it unchanged, so the
# request and the log line hold it as written whether or not the worker redacts.
NOTE = "Re-ice at the relay before the pallet moves."
# A schema-valid answer, so the summary path takes the same branch before and after the
# student's edits; what that branch stores is not asserted here.
VALID_ANSWER = json.dumps(
    {
        "summary": "bounded synthetic summary",
        "handling_class": "thermal_excursion",
        "next_step": "operational_review",
        "procedure_id": "playbook-thermal-excursion",
        "response_id": "0123456789abcdef",
    },
    sort_keys=True,
)
READING = SensorReading(
    reading_id="reading-syn-001",
    shipment_id="shipment-syn-001",
    temperature_c=9.2,
    allowed_min_c=2.0,
    allowed_max_c=8.0,
    recorded_at=NOW,
    handling_note=NOTE,
    emulator_response="valid",
)
JOB = ExceptionJob(exception_id="exc-001", reading=READING, accepted_at=NOW)
EXCERPT = ProcedureExcerpt(
    document_id="playbook-thermal-excursion",
    chunk_id="playbook-thermal-excursion#0000",
    text="A thermal excursion begins the moment a probe reports a reading outside the range.",
    window_minutes=None,
)


def queued_record() -> ExceptionRecord:
    """Return the durable starting record for a worker test."""
    return ExceptionRecord(
        exception_id=JOB.exception_id,
        reading=READING,
        state=ExceptionState.QUEUED,
        accepted_at=NOW,
        updated_at=NOW,
    )


def _application(
    repository: MemoryRepository,
    provider: object,
    procedures: object | None = None,
    audit: RecordingAudit | None = None,
) -> WorkerApplication:
    """Compose the worker application around one repository, provider, and audit double."""
    return WorkerApplication(
        repository,
        provider,  # type: ignore[arg-type] - focused boundary fake
        procedures if procedures is not None else StaticProcedures(),  # type: ignore[arg-type]
        audit=audit if audit is not None else RecordingAudit(),
        clock=lambda: NOW,
    )


def test_the_finished_states_are_completed_failed_and_needs_review() -> None:
    """A redelivery of any finished identity is a replay, NEEDS_REVIEW included."""
    assert FINISHED_STATES == {
        ExceptionState.COMPLETED,
        ExceptionState.FAILED,
        ExceptionState.NEEDS_REVIEW,
    }


@pytest.mark.asyncio
async def test_model_request_carries_the_reading_the_note_the_procedure_and_the_response() -> None:
    """The request is the reading, the note, the excerpt, and the response selector."""
    repository = MemoryRepository(queued_record())
    provider = RecordingProvider()
    procedures = StaticProcedures()
    application = _application(repository, provider, procedures)

    await application.process(JOB, delivery_count=1)

    assert procedures.readings == [READING]
    request = provider.requests[0]
    assert request.exception_id == JOB.exception_id
    assert request.shipment_id == READING.shipment_id
    assert request.temperature_c == READING.temperature_c
    assert request.handling_note == NOTE
    assert request.procedure_id == EXCERPT.document_id
    assert request.procedure_excerpt == EXCERPT.text
    assert request.emulator_response == "valid"


@pytest.mark.asyncio
async def test_worker_logs_the_job_as_it_reads_it(caplog: pytest.LogCaptureFixture) -> None:
    """One log line names the job and carries the handling-note field."""
    repository = MemoryRepository(queued_record())
    application = _application(repository, RecordingProvider())

    with caplog.at_level(logging.INFO, logger="worker.use_cases"):
        await application.process(JOB, delivery_count=1)

    messages = [record.getMessage() for record in caplog.records]
    lines = [message for message in messages if message.startswith("reading job")]
    assert len(lines) == 1
    assert f"exception_id={JOB.exception_id}" in lines[0]
    assert f"handling_note={NOTE}" in lines[0]


@pytest.mark.parametrize(
    "state", [ExceptionState.COMPLETED, ExceptionState.FAILED, ExceptionState.NEEDS_REVIEW]
)
@pytest.mark.asyncio
async def test_finished_duplicate_is_acknowledged_without_provider_call(
    state: ExceptionState,
) -> None:
    """A duplicate delivery of a finished identity must not repeat a provider effect."""
    record = queued_record().model_copy(update={"state": state, "summary": "already finished"})
    repository = MemoryRepository(record)
    provider = RecordingProvider()
    procedures = StaticProcedures()
    audit = RecordingAudit()
    application = _application(repository, provider, procedures, audit)

    disposition = await application.process(JOB, delivery_count=2)

    assert disposition is ProcessingDisposition.ACK_EXISTING
    assert provider.calls == 0
    assert procedures.readings == []
    assert audit.events == []
    assert repository.record.state is state


@pytest.mark.asyncio
async def test_delivery_without_a_durable_record_is_named_explicitly() -> None:
    """A broken persistence-before-publish invariant must not look like a safe replay."""
    repository = MemoryRepository(queued_record())
    provider = RecordingProvider()
    application = _application(repository, provider)
    missing_job = JOB.model_copy(update={"exception_id": "exc-missing"})

    disposition = await application.process(missing_job, delivery_count=1)

    assert disposition is ProcessingDisposition.ACK_MISSING
    assert provider.calls == 0


@pytest.mark.asyncio
async def test_inflight_duplicate_waits_without_repeating_provider_work() -> None:
    """A second delivery must not run the provider while the first is processing."""
    repository = MemoryRepository(
        queued_record().model_copy(update={"state": ExceptionState.PROCESSING})
    )
    provider = RecordingProvider()
    application = _application(repository, provider)

    disposition = await application.process(JOB, delivery_count=2)

    assert disposition is ProcessingDisposition.RETRY
    assert provider.calls == 0


@pytest.mark.asyncio
async def test_third_inflight_delivery_records_terminal_failure() -> None:
    """A crash-stranded processing record must not remain pending forever."""
    repository = MemoryRepository(
        queued_record().model_copy(update={"state": ExceptionState.PROCESSING})
    )
    provider = RecordingProvider()
    application = _application(repository, provider)

    disposition = await application.process(JOB, delivery_count=3)

    assert disposition is ProcessingDisposition.ACK
    assert repository.record.state is ExceptionState.FAILED
    assert repository.record.failure_reason == "processing_attempts_exhausted"
    assert provider.calls == 0


@pytest.mark.asyncio
async def test_provider_failure_retries_before_terminal_attempt() -> None:
    """A non-final provider failure must leave the message pending for retry."""
    repository = MemoryRepository(queued_record())
    application = _application(repository, RecordingProvider(fail=True))

    disposition = await application.process(JOB, delivery_count=2)

    assert disposition is ProcessingDisposition.RETRY
    assert repository.record.state is ExceptionState.QUEUED


@pytest.mark.asyncio
async def test_third_provider_failure_is_recorded_and_acknowledged() -> None:
    """The third failure must become an observable terminal outcome, not a review."""
    repository = MemoryRepository(queued_record())
    application = _application(repository, RecordingProvider(fail=True))

    disposition = await application.process(JOB, delivery_count=3)

    assert disposition is ProcessingDisposition.ACK
    assert repository.record.state is ExceptionState.FAILED
    assert repository.record.failure_reason == "model_provider_exhausted"


@pytest.mark.asyncio
async def test_unreachable_corpus_store_retries_without_calling_the_provider() -> None:
    """A retrieval failure spends the attempt and leaves the job for redelivery."""
    repository = MemoryRepository(queued_record())
    provider = RecordingProvider()
    application = _application(repository, provider, StaticProcedures(fail=True))

    disposition = await application.process(JOB, delivery_count=1)

    assert disposition is ProcessingDisposition.RETRY
    assert repository.record.state is ExceptionState.QUEUED
    assert provider.calls == 0


@pytest.mark.asyncio
async def test_unreachable_corpus_store_at_the_final_delivery_exhausts_the_attempts() -> None:
    """At the last delivery a retrieval failure is the attempts running out, nothing else."""
    repository = MemoryRepository(queued_record())
    provider = RecordingProvider()
    application = _application(repository, provider, StaticProcedures(fail=True))

    disposition = await application.process(JOB, delivery_count=3)

    assert disposition is ProcessingDisposition.ACK
    assert repository.record.state is ExceptionState.FAILED
    assert repository.record.failure_reason == "processing_attempts_exhausted"
    assert provider.calls == 0


@pytest.mark.asyncio
async def test_terminal_provider_failure_is_recorded_on_the_first_delivery() -> None:
    """A terminal failure must not wait for the retryable-exhaustion budget."""
    repository = MemoryRepository(queued_record())
    provider = TerminalRecordingProvider()
    application = _application(repository, provider)

    disposition = await application.process(JOB, delivery_count=1)

    assert disposition is ProcessingDisposition.ACK
    assert repository.record.state is ExceptionState.FAILED
    assert repository.record.failure_reason == "model_provider_terminal_failure"
    assert provider.calls == 1


@pytest.mark.asyncio
async def test_terminal_provider_failure_at_the_final_delivery_is_still_distinct() -> None:
    """Even at the last delivery, a terminal outcome keeps its own failure reason.

    A retryable failure exhausted at the final delivery also reaches FAILED/ACK,
    so disposition and state alone cannot tell the two outcomes apart there. The
    failure reason is the only observable that must still distinguish them.
    """
    repository = MemoryRepository(queued_record())
    provider = TerminalRecordingProvider()
    application = _application(repository, provider)

    disposition = await application.process(JOB, delivery_count=3)

    assert disposition is ProcessingDisposition.ACK
    assert repository.record.state is ExceptionState.FAILED
    assert repository.record.failure_reason == "model_provider_terminal_failure"
    assert repository.record.failure_reason != "model_provider_exhausted"
