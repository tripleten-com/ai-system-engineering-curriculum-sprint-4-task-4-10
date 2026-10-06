"""Coldline.

===================

File:              src/ports/model_provider.py
Component:         Port — Model Provider
Purpose:           Define the provider-neutral model-execution port.
Interacts With:    Use cases and provider adapters
Sprint/Task:       Sprint 4 — Project 4
Concepts:          Dependency inversion, provider-neutral interface
Tools:             Python 3.12
"""

from typing import Protocol, runtime_checkable

from domain.contracts import ModelAnswer, ModelRequest


@runtime_checkable
class ModelProvider(Protocol):
    """Generate one answer for an exception summary request.

    From the Project 4 opening checkpoint the port returns the provider's raw
    answer text. Turning that text into a stored summary is the caller's
    responsibility, which is what lets a later Task put a validation boundary
    between the provider and the record without changing this contract.
    """

    async def summarize(self, request: ModelRequest) -> ModelAnswer:
        """Return the provider's raw answer for one request."""
        ...
