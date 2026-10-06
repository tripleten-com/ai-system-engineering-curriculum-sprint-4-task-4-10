"""Coldline.

===================

File:              src/ports/object_store.py
Component:         Port — Object Store
Purpose:           Define the provider-neutral object-storage port.
Interacts With:    Use cases and provider adapters
Sprint/Task:       Sprint 2 — Project 2
Concepts:          Dependency inversion, provider-neutral interface
Tools:             Python 3.12
"""

from typing import Protocol, runtime_checkable


@runtime_checkable
class ObjectStore(Protocol):
    """Read and write immutable evidence objects."""

    async def read(self, key: str) -> bytes:
        """Return the bytes stored under a provider-neutral key."""
        ...

    async def write(self, key: str, value: bytes) -> None:
        """Store bytes under a provider-neutral key."""
        ...

    async def list_keys(self, prefix: str) -> list[str]:
        """Return the stored keys under one provider-neutral prefix.

        Sprint 2 adds this operation so corpus and provenance artifacts can be
        enumerated from application code and from diagnostics without any
        component importing a cloud SDK. Keys are returned in ascending order.
        """
        ...
