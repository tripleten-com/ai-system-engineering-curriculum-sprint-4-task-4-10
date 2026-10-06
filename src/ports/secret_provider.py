"""Coldline.

===================

File:              src/ports/secret_provider.py
Component:         Port — Secret Provider
Purpose:           Define the provider-neutral secret-access port.
Interacts With:    Use cases and provider adapters
Sprint/Task:       Sprint 1 — Project 1
Concepts:          Dependency inversion, provider-neutral interface
Tools:             Python 3.12
"""

from typing import Protocol, runtime_checkable


@runtime_checkable
class SecretProvider(Protocol):
    """Read an application secret without exposing provider details."""

    async def read(self, name: str) -> str:
        """Return one secret value by provider-neutral name."""
        ...
