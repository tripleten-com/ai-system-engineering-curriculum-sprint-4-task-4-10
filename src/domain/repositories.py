"""Coldline.

===================

File:              src/domain/repositories.py
Component:         Domain — Repositories
Purpose:           Define internal persistence collaborators outside the five application ports.
Interacts With:    API and worker use cases, the document repository implementation
Sprint/Task:       Sprint 4 — Project 4
Concepts:          Business rules, immutable contracts, state, scoped reads
Tools:             Python 3.12

Task 4.3 extends ``ExceptionRepository.transition`` with the three fields the output
policy stores: the validated ``handling_class`` and ``next_step`` of a ``COMPLETED``
record, and the ``rejection_reason`` code of a ``NEEDS_REVIEW`` record.
"""

from collections.abc import Sequence
from typing import Protocol

from domain.contracts import (
    AccessTier,
    AuthorizationContext,
    ChunkRecord,
    DocumentRecord,
    ExceptionRecord,
    ExceptionState,
)


class StateConflict(RuntimeError):
    """Report a concurrent exception-state transition outside the expected set."""


class RepositoryError(RuntimeError):
    """Report that a persistence operation could not complete.

    An implementation raises this instead of letting a driver exception reach a
    caller, so application code never has to recognize a PostgreSQL error.
    """


def readable(scope: AuthorizationContext, tenant_id: str, access_tier: AccessTier) -> bool:
    """Return whether one caller may read content with one label.

    This is the scoped-read rule in one place, stated once so a query and a
    check cannot disagree about it:

    - the tenancy must match exactly, and
    - a `standard` caller reads `standard` content only, while a `restricted`
      caller reads both tiers of its own tenancy.

    A repository implementation is expected to express the same rule as SQL
    constraints rather than to call this function on fetched rows: filtering
    after the fact still moves other tenants' rows through the process.
    """
    if tenant_id != scope.tenant_id:
        return False
    return access_tier is AccessTier.STANDARD or scope.clearance is AccessTier.RESTRICTED


class ExceptionRepository(Protocol):
    """Persist and transition exception records without exposing a provider."""

    async def get(self, exception_id: str) -> ExceptionRecord | None:
        """Return one exception record when it exists."""
        ...

    async def create(self, record: ExceptionRecord) -> ExceptionRecord:
        """Create a record or return the existing idempotent record."""
        ...

    async def transition(
        self,
        exception_id: str,
        expected: set[ExceptionState],
        target: ExceptionState,
        *,
        summary: str | None = None,
        failure_reason: str | None = None,
        handling_class: str | None = None,
        next_step: str | None = None,
        rejection_reason: str | None = None,
    ) -> ExceptionRecord:
        """Apply one compare-and-set state transition.

        ``summary``, ``handling_class``, ``next_step`` and ``rejection_reason``
        are stored when given and otherwise keep their current value;
        ``failure_reason`` is set on every transition, so a state that is not
        ``FAILED`` clears it. The output policy decides which fields a
        ``COMPLETED`` and a ``NEEDS_REVIEW`` transition carry.
        """
        ...


class DocumentRepository(Protocol):
    """Read and write documents and their chunks for the application.

    This is the application-facing data layer. The supplied baseline loader
    puts the fixed corpus in place at startup and the supplied retrieval
    adapter reads it; neither of them serves the application's own reads and
    writes, and neither substitutes for this interface.

    Four requirements apply to every operation, and each is checked:

    1. **Real persistence.** Writes reach PostgreSQL and are visible to a
       separate connection after they commit. An in-memory store fails.
    2. **Domain mapping.** A row becomes a `DocumentRecord` or `ChunkRecord`
       with its access label and its whole provenance record intact. Losing a
       custodian, a revision, or a timestamp is a failure, not a detail.
    3. **Scoped reads.** Every read is constrained by the caller's scope inside
       the SQL, following `readable` above. A read that fetches other
       tenancies' rows and filters them afterwards is not scoped.
    4. **Atomic multi-record writes.** A document and its chunks commit
       together or not at all. A failure part-way through leaves no document
       row and no chunk row.
    """

    async def save_document(self, document: DocumentRecord, chunks: Sequence[ChunkRecord]) -> None:
        """Insert one document and all of its chunks in one transaction.

        Every chunk must belong to `document`. The whole operation commits
        together: if any chunk insert fails, the document insert is rolled back
        too and the store is left exactly as it was.

        Raises:
            RepositoryError: the write could not complete. Nothing is
                persisted when this is raised.

        """
        ...

    async def get_document(
        self, document_id: str, *, scope: AuthorizationContext
    ) -> DocumentRecord | None:
        """Return one document, or None when the scope may not read it.

        A document the scope may not read is indistinguishable from a document
        that does not exist, so this returns None rather than raising: telling
        a caller that a document exists but is out of scope is itself a leak.
        """
        ...

    async def list_documents(self, *, scope: AuthorizationContext) -> list[DocumentRecord]:
        """Return every document the scope may read, ordered by identifier."""
        ...

    async def get_chunks(
        self, document_id: str, *, scope: AuthorizationContext
    ) -> list[ChunkRecord]:
        """Return the readable chunks of one document, ordered by chunk index."""
        ...
