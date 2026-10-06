"""Coldline.

===================

File:              src/adapters/model/resilient.py
Component:         Adapter — Resilient
Purpose:           Bound one wrapped ModelProvider's per-attempt timeout and
                    attempt count, and classify its failures as retryable or
                    terminal before the worker ever sees them.
Interacts With:    ports.ModelProvider, domain.errors
Sprint/Task:       Sprint 4 — Project 4
Concepts:          Bounded timeout, bounded retry, failure classification
Tools:             Python 3.12, asyncio
"""

import asyncio
from collections.abc import Awaitable, Callable

from domain.contracts import ModelAnswer, ModelRequest
from domain.errors import RetryableProviderError, TerminalProviderError
from ports import ModelProvider

Classifier = Callable[[BaseException], bool]


def classify_default(exc: BaseException) -> bool:
    """Return True when ``exc`` may succeed on a later attempt.

    A per-attempt timeout is always retryable. An exception already carrying
    its own classification keeps it. Anything else is treated as retryable,
    matching the pre-resilience baseline of retrying an unclassified failure
    rather than discarding it silently.
    """
    if isinstance(exc, TerminalProviderError):
        return False
    if isinstance(exc, RetryableProviderError | TimeoutError):
        return True
    return True


class ResilientModelProvider:
    """Wrap one ModelProvider with a bounded timeout, retry, and classifier."""

    def __init__(
        self,
        inner: ModelProvider,
        *,
        timeout_seconds: float,
        max_attempts: int,
        backoff_seconds: float,
        classify: Classifier = classify_default,
        sleep: Callable[[float], Awaitable[None]] | None = None,
    ) -> None:
        """Configure positive bounds and accept an injectable clock for tests."""
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        if backoff_seconds < 0:
            raise ValueError("backoff_seconds must not be negative")
        self._inner = inner
        self._timeout_seconds = timeout_seconds
        self._max_attempts = max_attempts
        self._backoff_seconds = backoff_seconds
        self._classify = classify
        self._sleep = sleep or asyncio.sleep

    async def summarize(self, request: ModelRequest) -> ModelAnswer:
        """Return the inner provider's raw answer within bounded time and attempts.

        Each attempt gets its own timeout. A terminal failure — one the inner
        provider raised as ``TerminalProviderError``, or one ``classify``
        marks non-retryable — propagates immediately on its first occurrence;
        no attempt is spent retrying something that cannot succeed. Any other
        failure retries, with linear backoff, until ``max_attempts`` is spent,
        then raises ``RetryableProviderError`` so the caller can decide
        whether a further transport-level redelivery is worthwhile.
        """
        last_error: BaseException | None = None
        for attempt in range(1, self._max_attempts + 1):
            try:
                return await asyncio.wait_for(
                    self._inner.summarize(request), timeout=self._timeout_seconds
                )
            except TerminalProviderError:
                raise
            except Exception as exc:
                last_error = exc
                if not self._classify(exc):
                    raise TerminalProviderError(str(exc)) from exc
                if attempt < self._max_attempts and self._backoff_seconds:
                    await self._sleep(self._backoff_seconds * attempt)
        raise RetryableProviderError(
            f"model provider exhausted {self._max_attempts} attempt(s)"
        ) from last_error
