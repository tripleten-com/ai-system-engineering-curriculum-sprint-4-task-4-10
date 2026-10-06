"""Coldline.

===================

File:              src/adapters/persistence/document_repository.py
Component:         Adapter — Document repository
Purpose:           Implement the application-facing document and chunk data layer.
Interacts With:    PostgreSQL, domain contracts, the document service
Sprint/Task:       Sprint 2 — Project 2
Concepts:          Repository pattern, scoped reads, parameterized SQL, transactions
Tools:             Python 3.12, PostgreSQL, asyncpg

This is the reference data layer from Task 2.3, now supplied and protected. A
student's own Task 2.3 implementation stays in that Task's pull request and is
never required to match this file.
"""

import json
from collections.abc import Sequence
from typing import Any

import asyncpg
from opentelemetry import trace

from domain.contracts import (
    AccessLabel,
    AccessTier,
    AuthorizationContext,
    ChunkRecord,
    DocumentRecord,
    Provenance,
)
from domain.embedding import format_vector
from domain.repositories import RepositoryError

_TRACER = trace.get_tracer(__name__)

# The scoped-read predicate, written once. `$n` is the tenancy and `$n+1` is
# the caller's clearance; a `restricted` clearance admits both tiers of its own
# tenancy, and nothing else. Building this once keeps every read consistent and
# keeps the rule inside SQL rather than in Python after the fetch.
_SCOPE = "tenant_id = ${tenant} AND (access_tier = 'standard' OR ${clearance} = 'restricted')"

_DOCUMENT_COLUMNS = """
    document_id, title, body, tenant_id, access_tier,
    provenance_source_uri, provenance_custodian,
    provenance_revision, provenance_recorded_at
"""
_CHUNK_COLUMNS = """
    chunk_id, document_id, chunk_index, chunk_text, embedding,
    tenant_id, access_tier, provenance_source_uri,
    provenance_custodian, provenance_revision, provenance_recorded_at
"""


def _scope_clause(first: int) -> str:
    """Return the scope predicate with placeholders starting at one index."""
    return _SCOPE.format(tenant=first, clearance=first + 1)


class PostgresDocumentRepository:
    """Persist and read documents and chunks in PostgreSQL.

    Implements ``domain.repositories.DocumentRepository``.

    Two decisions carry the requirements:

    - Every value is bound as a parameter. No caller value is ever formatted
      into SQL text, which is why an apostrophe in a title and an injected
      predicate in an identifier both behave as ordinary data.
    - The document insert and every chunk insert share one transaction, opened
      before the document row is written. A failure anywhere inside it takes
      the document row with it, so a partial document cannot survive.
    """

    def __init__(self, pool: asyncpg.Pool) -> None:
        """Bind the repository to one initialized connection pool."""
        self._pool = pool

    async def save_document(self, document: DocumentRecord, chunks: Sequence[ChunkRecord]) -> None:
        """Insert one document and all of its chunks in one transaction."""
        foreign = sorted(
            chunk.chunk_id for chunk in chunks if chunk.document_id != document.document_id
        )
        if foreign:
            raise RepositoryError(f"chunks do not belong to {document.document_id}: {foreign}")

        with _TRACER.start_as_current_span(
            "documents.save", attributes={"coldline.document_id": document.document_id}
        ):
            try:
                async with self._pool.acquire() as connection:
                    # One transaction around both writes. Opening it before the
                    # document insert is what makes the rollback possible.
                    async with connection.transaction():
                        await connection.execute(
                            f"""
                            INSERT INTO documents ({_DOCUMENT_COLUMNS})
                            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                            """,  # noqa: S608 - column list is a module constant
                            document.document_id,
                            document.title,
                            document.body,
                            document.access.tenant_id,
                            document.access.access_tier.value,
                            document.provenance.source_uri,
                            document.provenance.custodian,
                            document.provenance.revision,
                            document.provenance.recorded_at,
                        )
                        for chunk in chunks:
                            await connection.execute(
                                f"""
                                INSERT INTO chunks ({_CHUNK_COLUMNS})
                                VALUES (
                                    $1, $2, $3, $4, $5::vector, $6, $7, $8, $9, $10, $11
                                )
                                """,  # noqa: S608 - column list is a module constant
                                chunk.chunk_id,
                                chunk.document_id,
                                chunk.chunk_index,
                                chunk.text,
                                format_vector(chunk.embedding),
                                chunk.access.tenant_id,
                                chunk.access.access_tier.value,
                                chunk.provenance.source_uri,
                                chunk.provenance.custodian,
                                chunk.provenance.revision,
                                chunk.provenance.recorded_at,
                            )
            except asyncpg.PostgresError as exc:
                raise RepositoryError(f"could not store {document.document_id}: {exc}") from exc
            except OSError as exc:
                raise RepositoryError("the database is unreachable") from exc

    async def get_document(
        self, document_id: str, *, scope: AuthorizationContext
    ) -> DocumentRecord | None:
        """Return one document, or None when the scope may not read it."""
        with _TRACER.start_as_current_span("documents.get"):
            try:
                row = await self._pool.fetchrow(
                    f"""
                    SELECT * FROM documents
                    WHERE document_id = $1 AND {_scope_clause(2)}
                    """,  # noqa: S608 - scope predicate is a module constant
                    document_id,
                    scope.tenant_id,
                    scope.clearance.value,
                )
            except asyncpg.PostgresError as exc:
                raise RepositoryError(f"could not read {document_id}: {exc}") from exc
        return _document(row) if row is not None else None

    async def list_documents(self, *, scope: AuthorizationContext) -> list[DocumentRecord]:
        """Return every document the scope may read, ordered by identifier."""
        with _TRACER.start_as_current_span("documents.list"):
            try:
                rows = await self._pool.fetch(
                    f"""
                    SELECT * FROM documents
                    WHERE {_scope_clause(1)}
                    ORDER BY document_id
                    """,  # noqa: S608 - scope predicate is a module constant
                    scope.tenant_id,
                    scope.clearance.value,
                )
            except asyncpg.PostgresError as exc:
                raise RepositoryError(f"could not list documents: {exc}") from exc
        return [_document(row) for row in rows]

    async def get_chunks(
        self, document_id: str, *, scope: AuthorizationContext
    ) -> list[ChunkRecord]:
        """Return the readable chunks of one document, ordered by chunk index."""
        with _TRACER.start_as_current_span("documents.chunks"):
            try:
                rows = await self._pool.fetch(
                    f"""
                    SELECT * FROM chunks
                    WHERE document_id = $1 AND {_scope_clause(2)}
                    ORDER BY chunk_index
                    """,  # noqa: S608 - scope predicate is a module constant
                    document_id,
                    scope.tenant_id,
                    scope.clearance.value,
                )
            except asyncpg.PostgresError as exc:
                raise RepositoryError(f"could not read chunks of {document_id}: {exc}") from exc
        return [_chunk(row) for row in rows]


def _label(row: asyncpg.Record) -> AccessLabel:
    """Map the two access columns to the domain label."""
    return AccessLabel(tenant_id=row["tenant_id"], access_tier=AccessTier(row["access_tier"]))


def _provenance(row: asyncpg.Record) -> Provenance:
    """Map the four provenance columns to the domain custody record."""
    return Provenance(
        source_uri=row["provenance_source_uri"],
        custodian=row["provenance_custodian"],
        revision=row["provenance_revision"],
        recorded_at=row["provenance_recorded_at"],
    )


def _document(row: asyncpg.Record) -> DocumentRecord:
    """Convert one document row to the canonical runtime contract."""
    return DocumentRecord(
        document_id=row["document_id"],
        title=row["title"],
        body=row["body"],
        access=_label(row),
        provenance=_provenance(row),
    )


def _chunk(row: asyncpg.Record) -> ChunkRecord:
    """Convert one chunk row to the canonical runtime contract.

    ``pgvector`` returns the embedding as its textual literal over the wire, so
    it is parsed back into floats here rather than handed on as a string.
    """
    return ChunkRecord(
        chunk_id=row["chunk_id"],
        document_id=row["document_id"],
        chunk_index=row["chunk_index"],
        text=row["chunk_text"],
        embedding=_embedding(row["embedding"]),
        access=_label(row),
        provenance=_provenance(row),
    )


def _embedding(value: Any) -> tuple[float, ...]:
    """Parse one stored vector value into a tuple of floats."""
    if isinstance(value, str):
        return tuple(float(part) for part in json.loads(value))
    return tuple(float(part) for part in value)
