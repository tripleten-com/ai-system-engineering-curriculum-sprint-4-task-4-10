"""Coldline.

===================

File:              src/adapters/persistence/idempotency.py
Component:         Adapter — PostgreSQL idempotency store
Purpose:           Claim idempotency keys and store completed responses durably.
Interacts With:    PostgreSQL, the domain idempotency contract, the API handler
Sprint/Task:       Sprint 2 — Project 2 / Task 2.5
Concepts:          Idempotent writes, claim ownership, atomic claim
Tools:             Python 3.12, PostgreSQL, asyncpg
"""

import asyncpg
from opentelemetry import trace

from domain.idempotency import (
    ClaimState,
    IdempotencyClaim,
    IdempotencyConflict,
    StoredResponse,
)

_TRACER = trace.get_tracer(__name__)
_CLAIM_ATTEMPTS = 3


class PostgresIdempotencyStore:
    """Store idempotency claims in PostgreSQL.

    Implements ``domain.idempotency.IdempotencyStore``. This adapter is
    supplied and protected: Task 2.5 asks a student to *apply* it, not to
    build a distributed locking system.

    Each claim attempt is one statement. ``INSERT ... ON CONFLICT DO NOTHING
    RETURNING`` either inserts the row and returns it, in which case this
    caller owns the key, or returns nothing, in which case somebody else got
    there first and the existing row says what to do next. Two concurrent
    duplicates therefore cannot both believe they own the key, and no
    read-then-write race exists to lose. If a concurrent release removes the
    row before the lookup, retry the atomic insertion before reporting ownership.
    """

    def __init__(self, pool: asyncpg.Pool) -> None:
        """Bind the store to one initialized connection pool."""
        self._pool = pool

    async def claim(self, key: str, operation_id: str) -> IdempotencyClaim:
        """Take ownership of one key, or report who already has it."""
        with _TRACER.start_as_current_span(
            "idempotency.claim", attributes={"coldline.operation_id": operation_id}
        ):
            for _ in range(_CLAIM_ATTEMPTS):
                inserted = await self._pool.fetchrow(
                    """
                    INSERT INTO idempotency_claims (idempotency_key, operation_id)
                    VALUES ($1, $2)
                    ON CONFLICT (idempotency_key) DO NOTHING
                    RETURNING idempotency_key, operation_id, claimed_at
                    """,
                    key,
                    operation_id,
                )
                if inserted is not None:
                    return IdempotencyClaim(
                        key=key,
                        operation_id=operation_id,
                        state=ClaimState.CLAIMED,
                        claimed_at=inserted["claimed_at"],
                    )

                existing = await self._pool.fetchrow(
                    "SELECT * FROM idempotency_claims WHERE idempotency_key = $1", key
                )
                if existing is None:
                    # A concurrent release won the race with this lookup. Only
                    # a successful insertion can grant this caller ownership.
                    continue
                if existing["operation_id"] != operation_id:
                    raise IdempotencyConflict(
                        "idempotency key is already in use by operation "
                        f"{existing['operation_id']!r}"
                    )
                if existing["completed_at"] is None:
                    return IdempotencyClaim(
                        key=key,
                        operation_id=operation_id,
                        state=ClaimState.IN_FLIGHT,
                        claimed_at=existing["claimed_at"],
                    )
                return IdempotencyClaim(
                    key=key,
                    operation_id=operation_id,
                    state=ClaimState.COMPLETED,
                    claimed_at=existing["claimed_at"],
                    response=StoredResponse(
                        status_code=existing["response_status"],
                        body=existing["response_body"],
                    ),
                )

            raise IdempotencyConflict(
                "idempotency key changed during concurrent claims; retry the request"
            )

    async def complete(self, key: str, operation_id: str, response: StoredResponse) -> None:
        """Record the response one completed operation produced."""
        with _TRACER.start_as_current_span("idempotency.complete"):
            updated = await self._pool.fetchrow(
                """
                UPDATE idempotency_claims
                SET completed_at = CURRENT_TIMESTAMP,
                    response_status = $3,
                    response_body = $4
                WHERE idempotency_key = $1
                  AND operation_id = $2
                  AND completed_at IS NULL
                RETURNING idempotency_key
                """,
                key,
                operation_id,
                response.status_code,
                response.body,
            )
        if updated is None:
            # Completing a key this caller does not own, or completing it
            # twice, would let a later replay answer with the wrong response.
            raise IdempotencyConflict(
                f"idempotency key {key!r} is not an in-flight claim for {operation_id!r}"
            )

    async def release(self, key: str, operation_id: str) -> None:
        """Give up an in-flight claim so a later attempt can retry."""
        with _TRACER.start_as_current_span("idempotency.release"):
            await self._pool.execute(
                """
                DELETE FROM idempotency_claims
                WHERE idempotency_key = $1
                  AND operation_id = $2
                  AND completed_at IS NULL
                """,
                key,
                operation_id,
            )
