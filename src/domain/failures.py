"""Coldline.

===================

File:              src/domain/failures.py
Component:         Domain — Failure types
Purpose:           Name the provider-neutral failures that cross a port boundary.
Interacts With:    Ports, adapters, API routes, and diagnostics
Sprint/Task:       Sprint 2 — Project 2
Concepts:          Provider-neutral errors, boundary translation
Tools:             Python 3.12
"""


class ObjectNotFound(LookupError):
    """Report that no object exists under a provider-neutral key.

    The adapter translates its provider's own missing-key error into this type
    so that application code never has to recognize a cloud SDK exception.
    """


class ObjectStoreUnavailable(RuntimeError):
    """Report that object storage could not be reached or answered an error."""


class RetrievalUnavailable(RuntimeError):
    """Report that the retrieval backend could not answer a query."""


class CorpusFixtureError(ValueError):
    """Report a supplied corpus fixture that does not satisfy its own contract."""
