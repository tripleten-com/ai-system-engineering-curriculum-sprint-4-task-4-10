"""Coldline.

===================

File:              tests/unit/adapters/test_resilient_model_provider.py
Component:         Unit tests — Test Resilient Model Provider
Purpose:           Unit tests for bounded timeout, retry, and failure classification.
Interacts With:    One isolated source responsibility
Sprint/Task:       Sprint 4 — Project 4
Concepts:          Fast feedback, failure paths, bounded resilience
Tools:             Python 3.12, pytest
"""

import asyncio

import pytest

from adapters.model.resilient import ResilientModelProvider
from domain.contracts import ModelAnswer, ModelRequest
from domain.errors import RetryableProviderError, TerminalProviderError

REQUEST = ModelRequest(
    exception_id="exc-001",
    shipment_id="shipment-syn-001",
    temperature_c=9.2,
    allowed_min_c=2.0,
    allowed_max_c=8.0,
    handling_note="Re-ice at the relay.",
    procedure_id="playbook-thermal-excursion",
    procedure_excerpt="A thermal excursion begins the moment a probe reports a reading.",
)


class ScriptedProvider:
    """Replay a fixed sequence of outcomes: a result, or an exception to raise."""

    def __init__(self, outcomes: list[BaseException | ModelAnswer]) -> None:
        """Accept one outcome per expected call, in order."""
        self._outcomes = list(outcomes)
        self.calls = 0

    async def summarize(self, request: ModelRequest) -> ModelAnswer:
        """Return or raise the next scripted outcome."""
        outcome = self._outcomes[self.calls]
        self.calls += 1
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


class HangingProvider:
    """Never return, so the wrapper's own timeout is what ends the call."""

    def __init__(self) -> None:
        """Track how many times the worker started a call."""
        self.calls = 0

    async def summarize(self, request: ModelRequest) -> ModelAnswer:
        """Start a call that outlives any bounded timeout under test."""
        self.calls += 1
        await asyncio.sleep(10)
        raise AssertionError("must not complete before the timeout fires")


SUCCESS = ModelAnswer(provider="deterministic-local", text='{"summary": "ok"}')


async def _no_sleep(_seconds: float) -> None:
    """Replace real backoff sleeps so retry tests run instantly."""


@pytest.mark.asyncio
async def test_success_on_first_attempt_needs_no_retry() -> None:
    """A clean first attempt must return without consuming a retry."""
    inner = ScriptedProvider([SUCCESS])
    provider = ResilientModelProvider(inner, timeout_seconds=1, max_attempts=3, backoff_seconds=0)

    result = await provider.summarize(REQUEST)

    assert result is SUCCESS
    assert inner.calls == 1


@pytest.mark.asyncio
async def test_retryable_failure_succeeds_on_a_later_attempt() -> None:
    """An unclassified failure must retry and may still succeed."""
    inner = ScriptedProvider([RuntimeError("transient"), SUCCESS])
    provider = ResilientModelProvider(
        inner, timeout_seconds=1, max_attempts=3, backoff_seconds=0, sleep=_no_sleep
    )

    result = await provider.summarize(REQUEST)

    assert result is SUCCESS
    assert inner.calls == 2


@pytest.mark.asyncio
async def test_retryable_failure_raises_once_attempts_are_exhausted() -> None:
    """A failure that never clears must stop at max_attempts, not loop forever."""
    inner = ScriptedProvider([RuntimeError("a"), RuntimeError("b"), RuntimeError("c")])
    provider = ResilientModelProvider(
        inner, timeout_seconds=1, max_attempts=3, backoff_seconds=0, sleep=_no_sleep
    )

    with pytest.raises(RetryableProviderError):
        await provider.summarize(REQUEST)

    assert inner.calls == 3


@pytest.mark.asyncio
async def test_terminal_failure_is_not_retried() -> None:
    """A terminal failure must propagate on the first attempt, spending no retry."""
    inner = ScriptedProvider([TerminalProviderError("invalid request"), SUCCESS])
    provider = ResilientModelProvider(
        inner, timeout_seconds=1, max_attempts=3, backoff_seconds=0, sleep=_no_sleep
    )

    with pytest.raises(TerminalProviderError):
        await provider.summarize(REQUEST)

    assert inner.calls == 1


@pytest.mark.asyncio
async def test_classifier_can_mark_an_exception_terminal_on_first_occurrence() -> None:
    """A caller-supplied classifier must be able to fail fast on its own exception types."""

    class QuotaExhausted(RuntimeError):
        """Represent a provider error the caller knows is never worth retrying."""

    def classify(exc: BaseException) -> bool:
        return not isinstance(exc, QuotaExhausted)

    inner = ScriptedProvider([QuotaExhausted("no budget left"), SUCCESS])
    provider = ResilientModelProvider(
        inner,
        timeout_seconds=1,
        max_attempts=3,
        backoff_seconds=0,
        classify=classify,
        sleep=_no_sleep,
    )

    with pytest.raises(TerminalProviderError):
        await provider.summarize(REQUEST)

    assert inner.calls == 1


@pytest.mark.asyncio
async def test_a_hanging_call_is_bounded_by_its_own_timeout() -> None:
    """A provider call that never returns must still end within the configured bound."""
    inner = HangingProvider()
    provider = ResilientModelProvider(
        inner, timeout_seconds=0.01, max_attempts=1, backoff_seconds=0
    )

    with pytest.raises(RetryableProviderError):
        await provider.summarize(REQUEST)

    assert inner.calls == 1


def test_bounds_must_be_positive() -> None:
    """A zero or negative bound is a configuration error, not a runtime one."""
    inner = ScriptedProvider([SUCCESS])
    with pytest.raises(ValueError):
        ResilientModelProvider(inner, timeout_seconds=0, max_attempts=1, backoff_seconds=0)
    with pytest.raises(ValueError):
        ResilientModelProvider(inner, timeout_seconds=1, max_attempts=0, backoff_seconds=0)
    with pytest.raises(ValueError):
        ResilientModelProvider(inner, timeout_seconds=1, max_attempts=1, backoff_seconds=-1)
