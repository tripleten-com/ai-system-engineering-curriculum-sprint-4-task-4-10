"""Coldline.

===================

File:              src/adapters/persistence/corpus_loader.py
Component:         Adapter — Baseline corpus loader
Purpose:           Ingest the supplied corpus from object storage into PostgreSQL.
Interacts With:    ObjectStore port, domain chunking, PostgreSQL documents and chunks
Sprint/Task:       Sprint 2 — Project 2
Concepts:          Deterministic ingestion, provenance preservation, idempotency
Tools:             Python 3.12, PostgreSQL, pgvector
"""

import json
from dataclasses import dataclass
from hashlib import blake2b

import asyncpg
from opentelemetry import trace

from domain.chunking import chunk_document
from domain.contracts import ChunkRecord, DocumentRecord
from domain.embedding import format_vector
from domain.failures import CorpusFixtureError
from ports import ObjectStore

_TRACER = trace.get_tracer(__name__)

CORPUS_PREFIX = "corpus/"
DOCUMENTS_KEY = f"{CORPUS_PREFIX}documents.jsonl"
PROVENANCE_KEY = f"{CORPUS_PREFIX}provenance.jsonl"


@dataclass(frozen=True)
class LoadReport:
    """Summarize one ingestion run in a form a check can compare exactly."""

    documents: int
    chunks: int
    tenants: tuple[str, ...]
    access_tiers: tuple[str, ...]
    corpus_digest: str


class CorpusLoader:
    """Read the supplied corpus through ObjectStore and write it to PostgreSQL.

    This is the *baseline* loader. It is curriculum-supplied and stays
    operational for the whole Sprint. It is not the application-facing
    document repository that Task 2.3 asks a student to implement, and it never
    substitutes for it: it exists to put the fixed corpus in place so retrieval
    has something to search.

    Ingestion is deterministic and idempotent. Chunk identifiers derive from
    the document identity and the chunk position, and each write upserts, so
    running it twice produces the same rows and the same report.

    Every chunk keeps the parent document's access label and provenance
    unchanged. The report's ``corpus_digest`` is computed from those preserved
    fields, so a check can detect a loader that silently dropped a label or a
    custody record.
    """

    def __init__(self, pool: asyncpg.Pool, object_store: ObjectStore) -> None:
        """Bind the loader to a pool and the published object-store port."""
        self._pool = pool
        self._object_store = object_store

    async def load(self) -> LoadReport:
        """Ingest the supplied corpus and return a comparable report."""
        with _TRACER.start_as_current_span("corpus_loader.load"):
            documents = await self._read_documents()
            chunks = [chunk for document in documents for chunk in chunk_document(document)]
            async with self._pool.acquire() as connection:
                async with connection.transaction():
                    await self._write_documents(connection, documents)
                    await self._write_chunks(connection, chunks)
            return _report(documents, chunks)

    async def _read_documents(self) -> list[DocumentRecord]:
        """Load and validate the corpus and its provenance side-file.

        Both artifacts are read through the ``ObjectStore`` port. No component
        here knows the storage is LocalStack S3, and no cloud SDK is imported
        by this module.
        """
        documents = [
            DocumentRecord.model_validate(payload)
            for payload in _json_lines(await self._object_store.read(DOCUMENTS_KEY), DOCUMENTS_KEY)
        ]
        if not documents:
            raise CorpusFixtureError(f"{DOCUMENTS_KEY} contains no documents")
        identifiers = [document.document_id for document in documents]
        if len(set(identifiers)) != len(identifiers):
            raise CorpusFixtureError(f"{DOCUMENTS_KEY} repeats a document identifier")

        provenance = {
            payload["document_id"]: payload
            for payload in _json_lines(
                await self._object_store.read(PROVENANCE_KEY), PROVENANCE_KEY
            )
        }
        # The side-file is the custody record. Ingesting a document whose
        # custody entry disagrees would make later provenance evidence
        # unreliable, so the mismatch fails the run instead.
        for document in documents:
            entry = provenance.get(document.document_id)
            if entry is None:
                raise CorpusFixtureError(f"no provenance entry for {document.document_id}")
            if (
                entry["revision"] != document.provenance.revision
                or entry["custodian"] != document.provenance.custodian
                or entry["source_uri"] != document.provenance.source_uri
            ):
                raise CorpusFixtureError(f"provenance entry disagrees with {document.document_id}")
        return sorted(documents, key=lambda document: document.document_id)

    async def _write_documents(
        self, connection: asyncpg.Connection, documents: list[DocumentRecord]
    ) -> None:
        """Upsert every supplied document with its label and provenance."""
        await connection.executemany(
            """
            INSERT INTO documents (
                document_id, title, body, tenant_id, access_tier,
                provenance_source_uri, provenance_custodian,
                provenance_revision, provenance_recorded_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (document_id) DO UPDATE SET
                title = EXCLUDED.title,
                body = EXCLUDED.body,
                tenant_id = EXCLUDED.tenant_id,
                access_tier = EXCLUDED.access_tier,
                provenance_source_uri = EXCLUDED.provenance_source_uri,
                provenance_custodian = EXCLUDED.provenance_custodian,
                provenance_revision = EXCLUDED.provenance_revision,
                provenance_recorded_at = EXCLUDED.provenance_recorded_at
            """,
            [
                (
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
                for document in documents
            ],
        )

    async def _write_chunks(
        self, connection: asyncpg.Connection, chunks: list[ChunkRecord]
    ) -> None:
        """Upsert every chunk with its embedding, label, and provenance."""
        await connection.executemany(
            """
            INSERT INTO chunks (
                chunk_id, document_id, chunk_index, chunk_text, embedding,
                tenant_id, access_tier, provenance_source_uri,
                provenance_custodian, provenance_revision, provenance_recorded_at
            ) VALUES ($1, $2, $3, $4, $5::vector, $6, $7, $8, $9, $10, $11)
            ON CONFLICT (chunk_id) DO UPDATE SET
                document_id = EXCLUDED.document_id,
                chunk_index = EXCLUDED.chunk_index,
                chunk_text = EXCLUDED.chunk_text,
                embedding = EXCLUDED.embedding,
                tenant_id = EXCLUDED.tenant_id,
                access_tier = EXCLUDED.access_tier,
                provenance_source_uri = EXCLUDED.provenance_source_uri,
                provenance_custodian = EXCLUDED.provenance_custodian,
                provenance_revision = EXCLUDED.provenance_revision,
                provenance_recorded_at = EXCLUDED.provenance_recorded_at
            """,
            [
                (
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
                for chunk in chunks
            ],
        )


def _json_lines(payload: bytes, key: str) -> list[dict[str, object]]:
    """Parse one JSON Lines artifact into mappings, or fail with its key."""
    records: list[dict[str, object]] = []
    for number, line in enumerate(payload.decode("utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise CorpusFixtureError(f"{key} line {number} is not valid JSON") from exc
        if not isinstance(record, dict):
            raise CorpusFixtureError(f"{key} line {number} is not a JSON object")
        records.append(record)
    return records


def _report(documents: list[DocumentRecord], chunks: list[ChunkRecord]) -> LoadReport:
    """Summarize an ingestion run and digest its preserved metadata."""
    digest = blake2b(digest_size=16)
    for chunk in sorted(chunks, key=lambda chunk: chunk.chunk_id):
        digest.update(
            "|".join(
                (
                    chunk.chunk_id,
                    chunk.document_id,
                    str(chunk.chunk_index),
                    chunk.access.tenant_id,
                    chunk.access.access_tier.value,
                    chunk.provenance.source_uri,
                    chunk.provenance.custodian,
                    chunk.provenance.revision,
                    chunk.provenance.recorded_at.isoformat(),
                )
            ).encode("utf-8")
        )
    return LoadReport(
        documents=len(documents),
        chunks=len(chunks),
        tenants=tuple(sorted({document.access.tenant_id for document in documents})),
        access_tiers=tuple(sorted({document.access.access_tier.value for document in documents})),
        corpus_digest=digest.hexdigest(),
    )
