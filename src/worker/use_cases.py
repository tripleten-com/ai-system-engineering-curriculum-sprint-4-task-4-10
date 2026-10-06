"""Coldline.

===================

File:              src/worker/use_cases.py
Component:         Worker — Use Cases
Purpose:           Coordinate one provider-neutral exception-processing attempt.
Interacts With:    LocalStack SQS, domain, ports, adapters, src/worker/guardrail.py,
                    src/common/audit.py, src/common/redactor.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          Background processing, retries, idempotency, failure classification,
                    retrieval, output validation, audit events, PII redaction
Tools:             Python 3.12

For each job the worker logs the reading it took, retrieves the matching procedure
through the Retriever port, sends the reading, the redacted handling note and the
procedure excerpt to the model provider, passes the provider's redacted answer through
the supplied output guardrail, and stores either the validated summary or the output
policy's fail-safe outcome, recording the four worker audit events of
``docs/security/audit-events.md`` on the way (the Task 4.3 completion, supplied here).

Supplied Task 4.4 completion, carried forward unchanged: the supplied redactor ``redact``
(``src/common/redactor.py``) is applied twice in ``WorkerApplication.process``, to the
handling note where it is first read from the job, before the log line and the model
request, and to the provider's raw answer before it is handed to ``validate_summary``.
This file is not student-editable in Task 4.5; the public check compares the diff. The
provider key never passes through here: the model client presents it per request
(``src/worker/bootstrap.py``, ``src/worker/config.py``).
"""

import logging
from collections.abc import Callable
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from common.audit import AuditEvent, AuditRecorder, answer_digest
from common.redactor import redact
from domain.contracts import ExceptionJob, ExceptionState, ModelRequest, SensorReading
from domain.errors import TerminalProviderError
from domain.failures import RetrievalUnavailable
from domain.repositories import ExceptionRepository
from ports import ModelProvider
from worker.guardrail import REVIEW_MESSAGE, RejectedSummary, validate_summary
from worker.procedures import ProcedureExcerpt

LOGGER = logging.getLogger(__name__)
# The finished states a repeated delivery replays without a new model call. From Task
# 4.3 NEEDS_REVIEW is finished too: the answer came back and was refused, and a
# redelivery must not ask the provider again.
FINISHED_STATES: frozenset[ExceptionState] = frozenset(
    {ExceptionState.COMPLETED, ExceptionState.FAILED, ExceptionState.NEEDS_REVIEW}
)


class ProcessingDisposition(StrEnum):
    """Tell the transport loop whether to acknowledge or retry a delivery."""

    ACK = "ACK"
    ACK_EXISTING = "ACK_EXISTING"
    ACK_MISSING = "ACK_MISSING"
    RETRY = "RETRY"


class ProcedureSource(Protocol):
    """Find the procedure excerpt for one reading."""

    async def find(self, reading: SensorReading) -> ProcedureExcerpt:
        """Return the excerpt, or an empty one when nothing matched."""
        ...


class WorkerApplication:
    """Apply bounded model processing to one durable exception job."""

    def __init__(
        self,
        repository: ExceptionRepository,
        provider: ModelProvider,
        procedures: ProcedureSource,
        *,
        audit: AuditRecorder,
        clock: Callable[[], datetime],
        maximum_attempts: int = 3,
    ) -> None:
        """Receive collaborators, the audit sink, and a positive attempt limit."""
        if maximum_attempts < 1:
            raise ValueError("maximum_attempts must be positive")
        self._repository = repository
        self._provider = provider
        self._procedures = procedures
        self._audit = audit
        self._clock = clock
        self._maximum_attempts = maximum_attempts

    async def process(
        self,
        job: ExceptionJob,
        *,
        delivery_count: int,
    ) -> ProcessingDisposition:
        """Process one delivery and tell the queue whether it can be acknowledged.

        Finished identities (completed, failed, or awaiting review) are safe
        replays and need no new model call. In-flight work is retried until the
        third delivery. A provider result is redacted, checked against the output
        schema and persisted, as the validated summary or as the fail-safe
        outcome, before ``ACK`` is returned. A provider failure the provider
        itself classified as terminal fails immediately, on the first delivery,
        without spending a redelivery on an outcome that cannot change. Any other
        provider failure, and a retrieval backend that cannot answer, returns
        ``RETRY`` unless the delivery limit is exhausted. A missing record
        returns a distinct acknowledgement so the runtime can expose the broken
        persistence-before-publish invariant.
        """
        # The handling note is redacted where it is first read from the job, so the
        # log line below and the model request carry the placeholders, never the
        # detail. The stored reading and the queued job, written before this worker
        # ran, keep the raw note; that residual is the lesson's, not this method's.
        handling_note = redact(job.reading.handling_note)
        LOGGER.info(
            "reading job exception_id=%s shipment_id=%s handling_note=%s",
            job.exception_id,
            job.reading.shipment_id,
            handling_note,
        )
        record = await self._repository.get(job.exception_id)
        if record is None:
            return ProcessingDisposition.ACK_MISSING
        if record.state in FINISHED_STATES:
            return ProcessingDisposition.ACK_EXISTING
        if record.state is ExceptionState.PROCESSING:
            if delivery_count >= self._maximum_attempts:
                await self._repository.transition(
                    job.exception_id,
                    {ExceptionState.PROCESSING},
                    ExceptionState.FAILED,
                    failure_reason="processing_attempts_exhausted",
                )
                return ProcessingDisposition.ACK
            return ProcessingDisposition.RETRY

        # PROCESSING is durable before the provider call starts. Recovery can
        # therefore distinguish work that never started from interrupted work.
        await self._repository.transition(
            job.exception_id,
            {ExceptionState.QUEUED},
            ExceptionState.PROCESSING,
        )
        # The first audit event: the request that started this processing, by reading id
        # and delivery, and no caller identity, because the intake is unauthenticated.
        await self._audit.record(
            AuditEvent.PROCESSING_REQUESTED,
            exception_id=job.exception_id,
            details={
                "reading_id": job.reading.reading_id,
                "delivery_count": delivery_count,
            },
        )

        try:
            procedure = await self._procedures.find(job.reading)
        except RetrievalUnavailable:
            # The corpus store did not answer. That is this attempt failing,
            # not the provider, so it spends one processing attempt and is
            # otherwise retried like any interrupted attempt.
            if delivery_count >= self._maximum_attempts:
                await self._repository.transition(
                    job.exception_id,
                    {ExceptionState.PROCESSING},
                    ExceptionState.FAILED,
                    failure_reason="processing_attempts_exhausted",
                )
                return ProcessingDisposition.ACK
            await self._repository.transition(
                job.exception_id,
                {ExceptionState.PROCESSING},
                ExceptionState.QUEUED,
            )
            return ProcessingDisposition.RETRY

        try:
            answer = await self._provider.summarize(
                ModelRequest(
                    exception_id=job.exception_id,
                    shipment_id=job.reading.shipment_id,
                    temperature_c=job.reading.temperature_c,
                    allowed_min_c=job.reading.allowed_min_c,
                    allowed_max_c=job.reading.allowed_max_c,
                    handling_note=handling_note,
                    procedure_id=procedure.document_id,
                    procedure_excerpt=procedure.text,
                    emulator_response=job.reading.emulator_response,
                )
            )
        except TerminalProviderError:
            # The provider already decided a retry cannot succeed. Recording
            # the failure now, instead of after wasted redeliveries, is the
            # whole point of classifying it at the provider boundary.
            await self._repository.transition(
                job.exception_id,
                {ExceptionState.PROCESSING},
                ExceptionState.FAILED,
                failure_reason="model_provider_terminal_failure",
            )
            return ProcessingDisposition.ACK
        except Exception:  # noqa: BLE001 - the inherited worker retries any failure
            if delivery_count >= self._maximum_attempts:
                await self._repository.transition(
                    job.exception_id,
                    {ExceptionState.PROCESSING},
                    ExceptionState.FAILED,
                    failure_reason="model_provider_exhausted",
                )
                return ProcessingDisposition.ACK
            await self._repository.transition(
                job.exception_id,
                {ExceptionState.PROCESSING},
                ExceptionState.QUEUED,
            )
            return ProcessingDisposition.RETRY

        # The answer came back: record its digest and length, never its text. The digest
        # is of the answer as the provider returned it (docs/security/audit-events.md).
        await self._audit.record(
            AuditEvent.MODEL_RESPONDED,
            exception_id=job.exception_id,
            details={
                "provider": answer.provider,
                "answer_digest": answer_digest(answer.text),
                "answer_length": len(answer.text),
            },
        )

        # The provider's answer can carry a contact detail the note never held, so
        # the raw answer is redacted before the guardrail sees it: the schema then
        # checks the text that will be stored, placeholders included. A placeholder
        # holds no quote, backslash or line break, so a JSON answer stays JSON.
        redacted_answer = redact(answer.text)

        # The output boundary: nothing from the answer is stored until the whole
        # document has passed the schema. A rejection is the output policy's fail-safe
        # outcome, and it is never retried: a retry would hide the refusal instead of
        # recording it. `outcome_stored` is recorded immediately before the terminal
        # transition: a read can return the outcome only once the transition has
        # stored it, so the event always precedes the summary read in the trail
        # without a cross-store transaction.
        verdict = validate_summary(redacted_answer)
        if isinstance(verdict, RejectedSummary):
            await self._audit.record(
                AuditEvent.OUTPUT_REJECTED,
                exception_id=job.exception_id,
                details={"reason_code": verdict.code},
            )
            await self._audit.record(
                AuditEvent.OUTCOME_STORED,
                exception_id=job.exception_id,
                details={
                    "state": ExceptionState.NEEDS_REVIEW.value,
                    "summary": REVIEW_MESSAGE,
                },
            )
            await self._repository.transition(
                job.exception_id,
                {ExceptionState.PROCESSING},
                ExceptionState.NEEDS_REVIEW,
                summary=REVIEW_MESSAGE,
                rejection_reason=verdict.code,
            )
            return ProcessingDisposition.ACK

        await self._audit.record(
            AuditEvent.OUTPUT_VALIDATED,
            exception_id=job.exception_id,
            details={
                "handling_class": verdict.handling_class,
                "next_step": verdict.next_step,
            },
        )
        await self._audit.record(
            AuditEvent.OUTCOME_STORED,
            exception_id=job.exception_id,
            details={
                "state": ExceptionState.COMPLETED.value,
                "summary": verdict.summary,
            },
        )
        # Terminal persistence happens before the transport loop acknowledges, and only
        # the validated fields are stored.
        await self._repository.transition(
            job.exception_id,
            {ExceptionState.PROCESSING},
            ExceptionState.COMPLETED,
            summary=verdict.summary,
            handling_class=verdict.handling_class,
            next_step=verdict.next_step,
        )
        return ProcessingDisposition.ACK
