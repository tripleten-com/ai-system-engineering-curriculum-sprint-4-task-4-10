"""Coldline.

===================

File:              src/domain/errors.py
Component:         Domain — Errors
Purpose:           Classify a model-provider failure as retryable or terminal.
Interacts With:    Ports, adapters, and worker use cases
Sprint/Task:       Sprint 3 — Project 3
Concepts:          Bounded retry, failure classification
Tools:             Python 3.12
"""


class ProviderError(Exception):
    """Describe one classified model-provider failure."""


class RetryableProviderError(ProviderError):
    """Report a model-provider failure that may succeed on a later attempt.

    Raised once a bounded provider wrapper has exhausted its own attempts; the
    caller decides whether a further transport-level redelivery is worthwhile.
    """


class TerminalProviderError(ProviderError):
    """Report a model-provider failure that will not succeed on any attempt.

    A caller must not spend a transport-level redelivery on this outcome.
    """
