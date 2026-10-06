"""Coldline.

===================

File:              tests/contract/retrieval_runtime.py
Component:         Contract tests — Retrieval runtime
Purpose:           Verify ingestion, the ObjectStore boundary, and both retrieval arms.
Interacts With:    PostgreSQL with pgvector, LocalStack S3, supplied adapters
Sprint/Task:       Sprint 2 — Project 2
Concepts:          Hybrid retrieval, provenance preservation, explicit initial authorization
Tools:             Python 3.12, PostgreSQL, pgvector, boto3
"""

import asyncio
import json

import asyncpg

from adapters.object_store import S3ObjectStore, create_s3_client
from adapters.persistence import CorpusLoader
from adapters.retriever import PostgresHybridRetriever
from domain.access import UnrestrictedAccessConstraints
from domain.contracts import (
    AccessTier,
    AuthorizationContext,
    RetrievalRequest,
    RetrievalStage,
)
from domain.embedding import EMBEDDING_DIMENSIONS

DATABASE_URL = "postgresql://coldline:coldline_local@postgres:5432/coldline"
S3_ENDPOINT = "http://localstack:4566"
S3_BUCKET = "coldline-corpus"
S3_REGION = "us-east-1"
S3_ACCESS_KEY_ID = "localstack-development-key"
S3_SECRET_ACCESS_KEY = "localstack-development-secret"


async def verify() -> None:
    """Verify the Sprint 2 retrieval platform against the real services."""
    store = S3ObjectStore(
        create_s3_client(
            endpoint_url=S3_ENDPOINT,
            region_name=S3_REGION,
            access_key_id=S3_ACCESS_KEY_ID,
            secret_access_key=S3_SECRET_ACCESS_KEY,
        ),
        bucket=S3_BUCKET,
    )
    pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=3)
    assert pool is not None
    try:
        await _verify_object_store_boundary(store)
        await _verify_ingestion(pool, store)
        await _verify_hybrid_arms(pool)
        await _verify_initial_authorization_behavior(pool)
    finally:
        await pool.close()
    print("Retrieval verification passed: object boundary, ingestion, arms, and fusion are valid.")


async def _verify_object_store_boundary(store: S3ObjectStore) -> None:
    """Read the corpus and its custody record through the published port."""
    keys = await store.list_keys("corpus/")
    assert keys == ["corpus/documents.jsonl", "corpus/provenance.jsonl"], keys
    payload = await store.read("corpus/documents.jsonl")
    documents = [json.loads(line) for line in payload.decode("utf-8").splitlines() if line.strip()]
    assert len(documents) == 18, len(documents)
    assert {document["access"]["tenant_id"] for document in documents} == {
        "tenant-baltic",
        "tenant-coldline-ops",
        "tenant-northwind",
    }


async def _verify_ingestion(pool: asyncpg.Pool, store: S3ObjectStore) -> None:
    """Ingestion must be deterministic and must preserve labels and custody."""
    payload = await store.read("corpus/documents.jsonl")
    documents = [json.loads(line) for line in payload.decode("utf-8").splitlines() if line.strip()]
    first = await CorpusLoader(pool, store).load()
    second = await CorpusLoader(pool, store).load()
    assert first == second, "ingestion is not idempotent"
    assert first.documents == 18, first.documents
    assert first.chunks > first.documents, first.chunks

    # Count the corpus, not the tables. Later Tasks write application documents
    # into the same tables, and a supplied platform check must not depend on
    # whatever else happens to be stored.
    corpus_ids = [document["document_id"] for document in documents]
    counted = await pool.fetchrow(
        """
        SELECT
            (SELECT count(*) FROM documents WHERE document_id = ANY($1::text[])) AS documents,
            (SELECT count(*) FROM chunks WHERE document_id = ANY($1::text[])) AS chunks
        """,
        corpus_ids,
    )
    assert counted["documents"] == first.documents, dict(counted)
    assert counted["chunks"] == first.chunks, dict(counted)

    # Every chunk keeps its parent's tenancy, tier, and custody record. A join
    # that finds any disagreement is a metadata loss, not a ranking problem.
    mismatched = await pool.fetchval(
        """
        SELECT count(*)
        FROM chunks c
        JOIN documents d ON d.document_id = c.document_id
        WHERE c.tenant_id <> d.tenant_id
           OR c.access_tier <> d.access_tier
           OR c.provenance_source_uri <> d.provenance_source_uri
           OR c.provenance_custodian <> d.provenance_custodian
           OR c.provenance_revision <> d.provenance_revision
           OR c.provenance_recorded_at <> d.provenance_recorded_at
        """
    )
    assert mismatched == 0, f"{mismatched} chunk(s) lost their document metadata"

    # Deterministic identifiers: the identifier is derivable from the document
    # and the chunk position, so a re-ingest cannot create a second row.
    bad_identity = await pool.fetchval(
        "SELECT count(*) FROM chunks WHERE chunk_id <> document_id || '#' || lpad("
        "chunk_index::text, 4, '0')"
    )
    assert bad_identity == 0, f"{bad_identity} chunk identifier(s) are not derived"

    dimensions = await pool.fetchval("SELECT vector_dims(embedding) FROM chunks LIMIT 1")
    assert dimensions == EMBEDDING_DIMENSIONS, dimensions
    empty_search = await pool.fetchval(
        "SELECT count(*) FROM chunks WHERE search_document IS NULL "
        "OR length(search_document::text) = 0"
    )
    assert empty_search == 0, f"{empty_search} chunk(s) have no text-search representation"


async def _verify_hybrid_arms(pool: asyncpg.Pool) -> None:
    """Both arms must contribute and fusion must record what it dropped."""
    retriever = PostgresHybridRetriever(pool, access_constraints=UnrestrictedAccessConstraints())
    result = await retriever.search_hybrid(
        RetrievalRequest(
            query_id="runtime-hybrid",
            text="documented containment decision escalation window",
            authorization=AuthorizationContext(
                tenant_id="tenant-northwind", clearance=AccessTier.STANDARD
            ),
            top_k=5,
            dense_weight=0.5,
            explain=True,
        )
    )
    dense = result.stage(RetrievalStage.DENSE)
    sparse = result.stage(RetrievalStage.SPARSE)
    fusion = result.stage(RetrievalStage.FUSION)
    authorization = result.stage(RetrievalStage.AUTHORIZATION)

    assert dense.admitted, "the dense arm returned nothing"
    assert sparse.admitted, "the sparse arm returned nothing"
    assert set(dense.admitted) != set(sparse.admitted), (
        "both arms returned the same candidate set, so this query cannot show that fusion "
        "combines two different rankings"
    )
    assert len(result.results) == 5, len(result.results)
    assert fusion.admitted == tuple(candidate.chunk_id for candidate in result.results)
    assert set(fusion.admitted) <= set(dense.admitted) | set(sparse.admitted)
    assert set(fusion.dropped) == (set(dense.admitted) | set(sparse.admitted)) - set(
        fusion.admitted
    )
    assert authorization.admitted, "the explained authorization stage reported no readable pool"

    # A different fusion weight must reorder the same candidate pool. This is
    # what makes the Task 2.7 parameter a real variable rather than a label.
    dense_only = await retriever.search_hybrid(
        RetrievalRequest(
            query_id="runtime-hybrid-dense",
            text="documented containment decision escalation window",
            authorization=AuthorizationContext(
                tenant_id="tenant-northwind", clearance=AccessTier.STANDARD
            ),
            top_k=5,
            dense_weight=1.0,
        )
    )
    assert dense_only.stage(RetrievalStage.FUSION).admitted != fusion.admitted, (
        "changing dense_weight from 0.5 to 1.0 did not change the fused ranking"
    )


async def _verify_initial_authorization_behavior(pool: asyncpg.Pool) -> None:
    """Record the Task 2.1 starting state: the context is carried, not enforced.

    This is deliberately asserted rather than left implicit. The supplied
    checkpoint reports ``authorization_enforced == False``, and a caller from
    one tenancy can still retrieve another tenancy's chunk. Task 2.4 is the
    Task that changes this, and this check fails the moment enforcement
    arrives early by accident.
    """
    retriever = PostgresHybridRetriever(pool, access_constraints=UnrestrictedAccessConstraints())
    result = await retriever.search_hybrid(
        RetrievalRequest(
            query_id="runtime-authorization-baseline",
            text="hazardous material spill evacuate transfer bay",
            authorization=AuthorizationContext(
                tenant_id="tenant-northwind", clearance=AccessTier.STANDARD
            ),
            top_k=5,
            dense_weight=0.5,
        )
    )
    assert result.authorization_enforced is False
    foreign = [
        candidate.chunk_id
        for candidate in result.results
        if candidate.access.tenant_id != "tenant-northwind"
    ]
    assert foreign, (
        "the supplied Task 2.1 checkpoint is expected to return other tenants' chunks; "
        "authorization filtering is Task 2.4's work"
    )


if __name__ == "__main__":
    asyncio.run(verify())
