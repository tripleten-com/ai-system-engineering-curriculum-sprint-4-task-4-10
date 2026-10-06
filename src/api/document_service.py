"""Coldline.

===================

File:              src/api/document_service.py
Component:         API — Document service
Purpose:           Coordinate application document reads and writes through the data layer.
Interacts With:    The document repository contract, domain chunking, the document routes
Sprint/Task:       Sprint 2 — Project 2
Concepts:          Application coordination, scoped reads, atomic writes
Tools:             Python 3.12
"""

from collections.abc import Callable

from domain.chunking import chunk_document
from domain.contracts import AuthorizationContext, ChunkRecord, DocumentRecord
from domain.repositories import DocumentRepository


class DocumentsUnavailable(RuntimeError):
    """Report that no document repository is composed into this application.

    This is the starter state. The message names the factory to fill rather
    than failing with an attribute error somewhere deeper.
    """


class DocumentService:
    """Serve application document operations through the composed data layer.

    The repository arrives through a provider rather than as a value because
    the connection pool is created during application startup, after this
    object is constructed. The provider returning ``None`` is a composition
    fact, not an error condition, so it surfaces as one clear failure at the
    boundary.
    """

    def __init__(self, provider: Callable[[], DocumentRepository | None]) -> None:
        """Receive a provider that resolves the composed repository at call time."""
        self._provider = provider

    @property
    def available(self) -> bool:
        """Return whether a document repository is composed."""
        return self._provider() is not None

    async def create(self, document: DocumentRecord) -> list[ChunkRecord]:
        """Chunk one document deterministically and persist both atomically.

        Chunking is supplied and shared with the baseline loader, so an
        application write and an ingested corpus document produce the same
        chunk identifiers for the same text.
        """
        chunks = chunk_document(document)
        await self._repository().save_document(document, chunks)
        return chunks

    async def get(self, document_id: str, *, scope: AuthorizationContext) -> DocumentRecord | None:
        """Return one document the scope may read."""
        return await self._repository().get_document(document_id, scope=scope)

    async def list_all(self, *, scope: AuthorizationContext) -> list[DocumentRecord]:
        """Return every document the scope may read.

        Named ``list_all`` rather than ``list`` so the annotation on the method
        below still resolves to the builtin type rather than to this method.
        """
        return await self._repository().list_documents(scope=scope)

    async def chunks(self, document_id: str, *, scope: AuthorizationContext) -> list[ChunkRecord]:
        """Return the readable chunks of one document."""
        return await self._repository().get_chunks(document_id, scope=scope)

    def _repository(self) -> DocumentRepository:
        """Resolve the composed repository or fail with an actionable message."""
        repository = self._provider()
        if repository is None:
            raise DocumentsUnavailable(
                "no document repository is composed; return your implementation from "
                "build_document_repository in src/api/extensions/wiring.py"
            )
        return repository
