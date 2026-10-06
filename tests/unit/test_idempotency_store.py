"""Coldline.

===================

File:              tests/unit/test_idempotency_store.py
Component:         Unit tests — PostgreSQL idempotency store
Purpose:           Preserve exclusive claim ownership during concurrent releases.
Interacts With:    Supplied persistence adapter and its database query boundary
Sprint/Task:       Sprint 2 — Project 2 / Task 2.5
Concepts:          Atomic ownership, bounded retries, replay
Tools:             Python 3.12, pytest
"""

from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest

from adapters.persistence.idempotency import PostgresIdempotencyStore
from domain.idempotency import ClaimState, IdempotencyConflict, StoredResponse

CLAIMED_AT = datetime(2026, 9, 7, tzinfo=UTC)


@pytest.mark.asyncio
async def test_released_claim_is_reacquired_before_reporting_ownership() -> None:
    """A release between conflict and lookup must not give two callers ownership."""
    in_flight = {
        "operation_id": "create_document",
        "claimed_at": CLAIMED_AT,
        "completed_at": None,
    }
    pool = AsyncMock()
    pool.fetchrow.side_effect = [None, None, in_flight, None, in_flight]
    store = PostgresIdempotencyStore(pool)

    first = await store.claim("duplicate-key", "create_document")
    duplicate = await store.claim("duplicate-key", "create_document")

    assert (first.state, duplicate.state) == (ClaimState.CLAIMED, ClaimState.IN_FLIGHT)
    assert first.claimed_at == CLAIMED_AT


@pytest.mark.asyncio
@pytest.mark.parametrize("completed", [False, True])
async def test_another_caller_can_win_the_released_claim(completed: bool) -> None:
    """A retry must respect a competing owner's in-flight or completed response."""
    existing = {
        "operation_id": "create_document",
        "claimed_at": CLAIMED_AT,
        "completed_at": CLAIMED_AT if completed else None,
        "response_status": 201,
        "response_body": '{"document_id":"one-write"}',
    }
    pool = AsyncMock()
    pool.fetchrow.side_effect = [None, None, None, existing]

    result = await PostgresIdempotencyStore(pool).claim("duplicate-key", "create_document")

    assert result.state == (ClaimState.COMPLETED if completed else ClaimState.IN_FLIGHT)
    assert result.claimed_at == CLAIMED_AT
    assert result.response == (
        StoredResponse(status_code=201, body=existing["response_body"]) if completed else None
    )


@pytest.mark.asyncio
async def test_retry_rejects_key_taken_by_another_operation() -> None:
    """A vanished row does not exempt a later owner from the operation check."""
    pool = AsyncMock()
    pool.fetchrow.side_effect = [None, None, None, {"operation_id": "accept_reading"}]

    with pytest.raises(IdempotencyConflict, match="accept_reading"):
        await PostgresIdempotencyStore(pool).claim("duplicate-key", "create_document")


@pytest.mark.asyncio
async def test_repeated_releases_fail_closed_after_bounded_attempts() -> None:
    """Contention cannot cause unbounded queries or manufacture claim ownership."""
    pool = AsyncMock()
    pool.fetchrow.return_value = None

    with pytest.raises(IdempotencyConflict, match="retry"):
        await PostgresIdempotencyStore(pool).claim("duplicate-key", "create_document")

    assert 2 < pool.fetchrow.await_count <= 6
