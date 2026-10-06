"""Coldline.

===================

File:              src/common/audit.py
Component:         Common — Audit sink
Purpose:           Record the audit events that reconstruct one interaction, each with the
                    exception id and the trace id of the request that recorded it.
Interacts With:    src/worker/use_cases.py, src/api/routes.py, docs/security/audit-events.md,
                    src/adapters/persistence/audit_store.py (PostgreSQL), the audit_events table
Sprint/Task:       Sprint 4 — Project 4 / Task 4.3
Concepts:          Audit trail, non-repudiation, evidence without credentials, trace correlation
Tools:             Python 3.12, OpenTelemetry

Supplied and settled: call it, do not edit it. ``AuditSink.record(event, exception_id=...,
details=...)`` builds one ``AuditRecord`` and appends it to the store it was composed with.
The sink fills in two things the caller must never get wrong: the trace id of the request
that is recording (read from the current OpenTelemetry span, so a worker event carries the
scenario's trace and a summary read carries its own request's trace) and the time. In the
running stack the store is the PostgreSQL ``audit_events`` table
(``adapters.persistence.PostgresAuditStore``); the student-test harness composes the same
sink over a memory store.

The sink stores exactly the ``details`` it is handed. It filters nothing, because what a
record may carry is a rule for the code that records (``docs/security/audit-events.md``),
and a sink that silently dropped a field would hide the very mistake the Task's credential
test exists to catch. ``answer_digest`` is the digest the model-response event carries in
place of the answer's text.

Call form, in the worker::

    from common.audit import AuditEvent, answer_digest

    await self._audit.record(
        AuditEvent.MODEL_RESPONDED,
        exception_id=job.exception_id,
        details={
            "provider": answer.provider,
            "answer_digest": answer_digest(answer.text),
            "answer_length": len(answer.text),
        },
    )

and in ``get_exception``, after the record is loaded and only when it holds a stored
outcome::

    await audit.record(
        AuditEvent.SUMMARY_READ,
        exception_id=record.exception_id,
        details={"subject": principal.subject, "role": principal.role},
    )
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol

from opentelemetry import trace

from domain.contracts import ExceptionState

# The states a record may be read in as a summary read: the two finished states that hold
# a stored outcome (a validated summary, or the output policy's fixed message).
STORED_OUTCOME_STATES: frozenset[ExceptionState] = frozenset(
    {ExceptionState.COMPLETED, ExceptionState.NEEDS_REVIEW}
)


class AuditEvent(StrEnum):
    """Name the events ``docs/security/audit-events.md`` lists, in the order they occur."""

    PROCESSING_REQUESTED = "processing_requested"
    MODEL_RESPONDED = "model_responded"
    OUTPUT_VALIDATED = "output_validated"
    OUTPUT_REJECTED = "output_rejected"
    OUTCOME_STORED = "outcome_stored"
    SUMMARY_READ = "summary_read"


# The worker's events for one interaction, in order; position three is one of two names.
WORKER_SEQUENCE: tuple[frozenset[str], ...] = (
    frozenset({AuditEvent.PROCESSING_REQUESTED.value}),
    frozenset({AuditEvent.MODEL_RESPONDED.value}),
    frozenset({AuditEvent.OUTPUT_VALIDATED.value, AuditEvent.OUTPUT_REJECTED.value}),
    frozenset({AuditEvent.OUTCOME_STORED.value}),
)


def answer_digest(text: str) -> str:
    """Return the SHA-256 hex digest of a provider's raw answer text.

    The model-response event carries this and the text's length instead of the text, so
    an audit reader can tell two answers apart and prove which one the worker checked
    without the audit table holding what the model wrote.
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def current_trace_id() -> str | None:
    """Return the current span's trace id as 32 lowercase hex characters, or None.

    Inside a request the API's server span, and inside the worker the processing span it
    continued from the queue message, are the current span; outside any span (a unit test
    with no tracer provider) there is no trace to name, and the record says so with None.
    """
    context = trace.get_current_span().get_span_context()
    if not context.is_valid:
        return None
    return format(context.trace_id, "032x")


@dataclass(frozen=True)
class AuditRecord:
    """One audit event: what happened, to which exception, in which request, with what fields.

    ``details`` holds the event's fields exactly as recorded; ``audit_id`` is the store's
    own sequence number once the record is stored, and None before.
    """

    event: str
    exception_id: str
    trace_id: str | None
    recorded_at: datetime
    details: dict[str, object] = field(default_factory=dict)
    audit_id: int | None = None

    def as_dict(self) -> dict[str, object]:
        """Return the record as plain JSON-compatible values, details included."""
        return {
            "audit_id": self.audit_id,
            "event": self.event,
            "exception_id": self.exception_id,
            "trace_id": self.trace_id,
            "recorded_at": self.recorded_at.isoformat(),
            "details": self.details,
        }

    def rendered(self) -> str:
        """Return the whole record as one line of JSON, every field and value included.

        This is the text the credential checks search: a token, a header name, or a secret
        value anywhere in the record, as a key or as a value, is in this string.
        """
        return json.dumps(self.as_dict(), sort_keys=True, default=str)


class AuditStore(Protocol):
    """Keep audit records and return them in order; the sink composes one of these."""

    async def append(self, record: AuditRecord) -> AuditRecord:
        """Store one record and return it with its ``audit_id`` filled in."""
        ...

    async def trail(self, exception_id: str) -> list[AuditRecord]:
        """Return every record of one exception, oldest first."""
        ...


class AuditRecorder(Protocol):
    """The one operation the worker and the route call: record one event."""

    async def record(
        self,
        event: AuditEvent | str,
        *,
        exception_id: str,
        details: Mapping[str, object] | None = None,
    ) -> AuditRecord:
        """Record one event for one exception, with the fields the event may carry."""
        ...


class AuditSink:
    """Build audit records with the current trace id and the time, and append them to a store."""

    def __init__(
        self,
        store: AuditStore,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        """Bind the sink to the store that keeps the records and to a clock."""
        self._store = store
        self._clock = clock

    async def record(
        self,
        event: AuditEvent | str,
        *,
        exception_id: str,
        details: Mapping[str, object] | None = None,
    ) -> AuditRecord:
        """Record one event for one exception and return the stored record.

        The trace id is the current span's; the recorder never passes one. ``details``
        are stored as given: ``docs/security/audit-events.md`` says what each event may
        carry, and the recording code is responsible for sending nothing else.
        """
        if not exception_id:
            raise ValueError("an audit event must name the exception it is about")
        record = AuditRecord(
            event=str(event),
            exception_id=exception_id,
            trace_id=current_trace_id(),
            recorded_at=self._clock(),
            details=dict(details or {}),
        )
        return await self._store.append(record)

    async def trail(self, exception_id: str) -> list[AuditRecord]:
        """Return the ordered events of one exception, as ``poe audit-trail`` prints them."""
        return await self._store.trail(exception_id)
