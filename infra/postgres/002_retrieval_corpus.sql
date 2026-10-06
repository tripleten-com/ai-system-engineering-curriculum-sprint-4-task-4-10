-- Coldline
-- File: infra/postgres/002_retrieval_corpus.sql
-- Component: Retrieval corpus initialization
-- Purpose: Create the document and chunk persistence schema with dense and sparse search fields.
-- Interacts With: PostgreSQL initializer, corpus loader, and hybrid retrieval adapter
-- Sprint/Task: Sprint 2 — Project 2
-- Concepts: Idempotent schema setup, hybrid search representations, access labels
-- Tools: PostgreSQL SQL, pgvector, PostgreSQL full-text search

-- pgvector supplies the `vector` column type used by the dense search arm.
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS documents (
    document_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    access_tier TEXT NOT NULL CHECK (access_tier IN ('standard', 'restricted')),
    provenance_source_uri TEXT NOT NULL,
    provenance_custodian TEXT NOT NULL,
    provenance_revision TEXT NOT NULL,
    provenance_recorded_at TIMESTAMPTZ NOT NULL
);

-- The chunk row carries its own copy of the parent's access label and
-- provenance. Retrieval filters and ranks chunks, so a query-time access
-- decision must not require a second join to stay correct, and retrieval
-- evidence must be able to name a chunk's custody without one either.
CREATE TABLE IF NOT EXISTS chunks (
    chunk_id TEXT PRIMARY KEY,
    document_id TEXT NOT NULL REFERENCES documents (document_id) ON DELETE CASCADE,
    chunk_index INTEGER NOT NULL CHECK (chunk_index >= 0),
    chunk_text TEXT NOT NULL,
    embedding vector(64) NOT NULL,
    tenant_id TEXT NOT NULL,
    access_tier TEXT NOT NULL CHECK (access_tier IN ('standard', 'restricted')),
    provenance_source_uri TEXT NOT NULL,
    provenance_custodian TEXT NOT NULL,
    provenance_revision TEXT NOT NULL,
    provenance_recorded_at TIMESTAMPTZ NOT NULL,
    search_document TSVECTOR GENERATED ALWAYS AS (to_tsvector('english', chunk_text)) STORED,
    UNIQUE (document_id, chunk_index)
);

CREATE INDEX IF NOT EXISTS chunks_search_document_idx ON chunks USING GIN (search_document);
CREATE INDEX IF NOT EXISTS chunks_tenant_idx ON chunks (tenant_id, access_tier);

-- The corpus is small and the dense arm must return the same ranking on every
-- run, so exact search is used deliberately instead of an approximate index.
-- An approximate index would trade that determinism for speed this corpus does
-- not need, and no production index-tuning claim follows from this choice.
