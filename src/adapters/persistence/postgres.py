"""Coldline.

===================

File:              src/adapters/persistence/postgres.py
Component:         Adapter — Postgres
Purpose:           Implement durable exception storage in PostgreSQL.
Interacts With:    Domain contracts, ports, and local providers
Sprint/Task:       Sprint 4 — Project 4
Concepts:          Boundary translation, deterministic infrastructure
Tools:             Python 3.12, PostgreSQL, OpenTelemetry
"""

import json
from typing import Any

import asyncpg
from opentelemetry import trace

from domain.contracts import ExceptionRecord, ExceptionState, SensorReading
from domain.repositories import StateConflict

_TRACER = trace.get_tracer(__name__)


class PostgresExceptionRepository:
    """Persist exception records with atomic compare-and-set transitions.

    The stable ``exception_id`` is the database primary key. State changes name
    their allowed starting states, so concurrent API or worker processes cannot
    silently overwrite a newer result.

    The reading is stored whole as JSON, and its handling note is also written
    to the ``handling_note`` column the Project 4 opening migration adds, so
    the raw note is one column away for the tooling later Tasks build over
    these records. The JSON column stays the record's source of truth. The
    Task 4.3 migration adds ``handling_class``, ``next_step`` and
    ``rejection_reason``, the fields the output policy stores.
    """

    def __init__(self, pool: asyncpg.Pool) -> None:
        """Bind the repository to one initialized connection pool."""
        self._pool = pool

    async def get(self, exception_id: str) -> ExceptionRecord | None:
        """Return one exception record when it exists."""
        with _TRACER.start_as_current_span("postgres.exceptions.get"):
            row = await self._pool.fetchrow(
                "SELECT * FROM exceptions WHERE exception_id = $1",
                exception_id,
            )
        return _record(row) if row is not None else None

    async def create(self, record: ExceptionRecord) -> ExceptionRecord:
        """Insert one identity or return the record won by a concurrent caller.

        ``ON CONFLICT DO NOTHING`` makes duplicate submission safe. A missing
        row after the conflict path indicates an infrastructure inconsistency
        and fails loudly instead of inventing state.
        """
        with _TRACER.start_as_current_span("postgres.exceptions.create"):
            row = await self._pool.fetchrow(
                """
                INSERT INTO exceptions (
                    exception_id, reading, state, accepted_at, updated_at, summary,
                    failure_reason, handling_note, handling_class, next_step, rejection_reason
                ) VALUES ($1, $2::jsonb, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                ON CONFLICT (exception_id) DO NOTHING
                RETURNING *
                """,
                record.exception_id,
                record.reading.model_dump_json(),
                record.state.value,
                record.accepted_at,
                record.updated_at,
                record.summary,
                record.failure_reason,
                record.reading.handling_note,
                record.handling_class,
                record.next_step,
                record.rejection_reason,
            )
        if row is not None:
            return _record(row)
        existing = await self.get(record.exception_id)
        if existing is None:
            raise RuntimeError("exception insert did not return or persist a record")
        return existing

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
        """Move one record only when its current state is explicitly allowed.

        Returning no row means another process moved the workflow first or the
        requested transition is invalid. Both cases surface as ``StateConflict``
        so the use case can choose replay, retry, or failure behavior. The
        summary and the three output-policy fields are written when given and
        kept otherwise; the failure reason is set on every transition.
        """
        with _TRACER.start_as_current_span("postgres.exceptions.transition"):
            row = await self._pool.fetchrow(
                """
                UPDATE exceptions
                SET state = $2,
                    summary = COALESCE($3, summary),
                    failure_reason = $4,
                    handling_class = COALESCE($6, handling_class),
                    next_step = COALESCE($7, next_step),
                    rejection_reason = COALESCE($8, rejection_reason),
                    updated_at = CURRENT_TIMESTAMP
                WHERE exception_id = $1 AND state = ANY($5::text[])
                RETURNING *
                """,
                exception_id,
                target.value,
                summary,
                failure_reason,
                [state.value for state in expected],
                handling_class,
                next_step,
                rejection_reason,
            )
        if row is None:
            raise StateConflict(f"invalid state transition for {exception_id}")
        return _record(row)


def _record(row: asyncpg.Record) -> ExceptionRecord:
    """Convert one database row to the canonical runtime contract."""
    reading_value: Any = row["reading"]
    if isinstance(reading_value, str):
        reading_value = json.loads(reading_value)
    return ExceptionRecord(
        exception_id=row["exception_id"],
        reading=SensorReading.model_validate(reading_value),
        state=ExceptionState(row["state"]),
        accepted_at=row["accepted_at"],
        updated_at=row["updated_at"],
        summary=row["summary"],
        failure_reason=row["failure_reason"],
        handling_class=row["handling_class"],
        next_step=row["next_step"],
        rejection_reason=row["rejection_reason"],
    )
