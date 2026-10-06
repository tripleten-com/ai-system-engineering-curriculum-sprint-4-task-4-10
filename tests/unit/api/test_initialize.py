"""Coldline.

===================

File:              tests/unit/api/test_initialize.py
Component:         Unit tests — Test Initialize
Purpose:           Unit tests for the initializer's bounded PostgreSQL connect retry.
Interacts With:    One isolated source responsibility
Sprint/Task:       Sprint 3 — Project 3
Concepts:          Fast feedback, failure paths, bounded retry, startup readiness
Tools:             Python 3.12, pytest, asyncpg
"""

from typing import Any

import asyncpg
import pytest

from api.initialize import POSTGRES_CONNECT_BUDGET_SECONDS, _connect_when_ready

DSN = "postgresql://coldline:coldline_local@postgres:5432/coldline"


class FakeClock:
    """Advance time only when the retry loop sleeps."""

    def __init__(self) -> None:
        """Start at zero with no recorded sleeps."""
        self.now = 0.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        """Return the current fake time."""
        return self.now

    async def sleep(self, seconds: float) -> None:
        """Record the delay and move the clock forward by it."""
        self.sleeps.append(seconds)
        self.now += seconds


class ScriptedConnect:
    """Raise each scripted error in turn, then return a connection."""

    def __init__(self, errors: list[BaseException]) -> None:
        """Keep the errors to raise before the connect succeeds."""
        self.errors = list(errors)
        self.calls: list[dict[str, Any]] = []
        self.connection = object()

    async def __call__(self, **kwargs: Any) -> object:
        """Fail with the next scripted error, or return the connection."""
        self.calls.append(kwargs)
        if self.errors:
            raise self.errors.pop(0)
        return self.connection


async def test_a_refused_connect_is_retried_with_backoff_until_postgres_listens() -> None:
    """PostgreSQL's first-boot server refuses TCP for a moment; that is not a failure."""
    clock = FakeClock()
    connect = ScriptedConnect(
        [ConnectionRefusedError(111, "Connect call failed"), ConnectionRefusedError(111, "again")]
    )

    connection = await _connect_when_ready(DSN, connect=connect, sleep=clock.sleep, clock=clock)

    assert connection is connect.connection
    assert len(connect.calls) == 3
    assert all(call["dsn"] == DSN for call in connect.calls)
    assert clock.sleeps == [0.5, 1.0]


async def test_a_server_that_is_still_starting_up_is_retried() -> None:
    """`the database system is starting up` (SQLSTATE 57P03) means wait, not fail."""
    clock = FakeClock()
    connect = ScriptedConnect([asyncpg.CannotConnectNowError("the database system is starting up")])

    connection = await _connect_when_ready(DSN, connect=connect, sleep=clock.sleep, clock=clock)

    assert connection is connect.connection
    assert clock.sleeps == [0.5]


async def test_the_retry_stops_at_its_budget_with_a_clear_error() -> None:
    """A database that never answers fails the initializer, naming the service and the wait."""
    clock = FakeClock()
    connect = ScriptedConnect([ConnectionRefusedError(111, "refused") for _ in range(100)])

    with pytest.raises(RuntimeError) as raised:
        await _connect_when_ready(DSN, connect=connect, sleep=clock.sleep, clock=clock)

    message = str(raised.value)
    assert "PostgreSQL" in message
    assert f"{POSTGRES_CONNECT_BUDGET_SECONDS:.0f} s" in message
    assert "docker compose logs postgres" in message
    assert isinstance(raised.value.__cause__, ConnectionRefusedError)
    # Bounded: about 30 s of waiting in total, with the delay capped rather than doubling
    # without limit.
    assert (
        POSTGRES_CONNECT_BUDGET_SECONDS - 1 <= sum(clock.sleeps) <= POSTGRES_CONNECT_BUDGET_SECONDS
    )
    assert max(clock.sleeps) <= 4.0
    assert len(connect.calls) < 20


async def test_each_attempt_is_bounded_so_one_hung_connect_cannot_spend_the_budget() -> None:
    """Every connect call carries its own timeout, never longer than the time left."""
    clock = FakeClock()
    connect = ScriptedConnect([TimeoutError(), TimeoutError()])

    await _connect_when_ready(DSN, connect=connect, sleep=clock.sleep, clock=clock)

    assert all(0 < call["timeout"] <= 5.0 for call in connect.calls)


async def test_a_wrong_credential_fails_at_once_instead_of_being_retried() -> None:
    """Only readiness failures are retried; a configuration error surfaces immediately."""
    clock = FakeClock()
    connect = ScriptedConnect([asyncpg.InvalidPasswordError("password authentication failed")])

    with pytest.raises(asyncpg.InvalidPasswordError):
        await _connect_when_ready(DSN, connect=connect, sleep=clock.sleep, clock=clock)

    assert len(connect.calls) == 1
    assert clock.sleeps == []
