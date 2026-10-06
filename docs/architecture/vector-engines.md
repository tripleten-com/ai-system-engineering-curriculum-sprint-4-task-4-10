# Vector engine technical profiles

Coldline stores its embeddings in PostgreSQL with the pgvector extension. As volume grows,
engineering teams weigh that against a dedicated vector engine such as Qdrant. This page is the
readable form of the two supplied profiles in
[`infra/profiles/vector-engines.yaml`](../../infra/profiles/vector-engines.yaml), which is what the
Task 2.8 checks read.

Nothing here is a recommendation, and nothing here was measured. Task 2.8 asks a factual question:
which storage layout does each engine implement?

## The shared retrieval need, and the assumptions declared for both

Comparing two engines against different needs, or against undisclosed assumptions, produces a
conclusion about the assumptions rather than about the engines. Both profiles answer the same
need under the same declared assumptions.

**The need.** Hybrid retrieval over a tenant-partitioned corpus of procedural documents: dense
similarity and full-text search over the same chunks, an access predicate applied at query time
rather than to the results, and per-stage evidence recoverable for one query.

**The declared assumptions.** A single write-primary datastore already owns the documents and
chunks; one deployment environment, with no multi-region or cross-account topology; corpus scale
in the thousands of chunks rather than the millions; the access predicate must be enforced inside
the search rather than after it; and operational ownership is one small team rather than a
dedicated platform group.

## The two storage layout patterns

| Code | Pattern |
|---|---|
| `integrated_relational_table` | Vector embeddings live as typed columns inside relational rows, beside the transactional entity data they belong to. One schema, one query planner, one durability boundary. |
| `dedicated_vector_payload_store` | Vectors and their metadata payloads live in collections maintained by a service built for similarity search. The vector store is a separate system from whichever database owns the entities. |

## PostgreSQL with pgvector

**Supplied as this repository's runtime**, from `pgvector/pgvector:pg16`, pinned by digest in
`compose.yaml`. The same pinned image reported PostgreSQL 16.15 and pgvector 0.8.6 during
Task 2.5 qualification on 2026-09-08. That version observation is not a Task 2.8 qualification.
The schema and write-path claims below are also inspectable in the supplied code.

**Storage and layout.** `infra/postgres/002_retrieval_corpus.sql` declares:

```sql
CREATE TABLE IF NOT EXISTS chunks (
    chunk_id TEXT PRIMARY KEY,
    document_id TEXT NOT NULL REFERENCES documents (document_id) ON DELETE CASCADE,
    chunk_text TEXT NOT NULL,
    embedding vector(64) NOT NULL,
    tenant_id TEXT NOT NULL,
    ...
```

The embedding is a column beside chunk text, the tenancy label, and provenance. The supplied
document writer inserts the document and its chunks, including embeddings, in one transaction.
An embedding does not automatically regenerate when someone changes the text column.

**Filtering.** Each search arm places its access predicate inside its SQL statement; the dense
arm also orders by vector distance. Inspect both arms' `WHERE` clauses in
`src/adapters/retriever/postgres_hybrid.py`. The planner controls execution order. In particular,
filtering with an approximate index can happen after an index scan and yield fewer matches.
Query-time enforcement alone does not prove complete recall. See the versioned
[pgvector filtering reference](https://github.com/pgvector/pgvector/blob/v0.8.6/README.md#filtering).

**Operational footprint.** One datastore owns documents, chunks, and stored embeddings. The
supplied write transaction does not need to propagate a second copy to another vector service.
Schema migrations change the objects they explicitly target; they need not change every table.

**Backup, restore, and synchronization.** A complete, consistent database backup can include
documents, chunks, and vectors together. Successfully restoring that full backup to a compatible
database recovers their shared snapshot. PostgreSQL also supports selective restores, whose
consistency needs separate attention. See the PostgreSQL 16 documentation for
[consistent dumps](https://www.postgresql.org/docs/16/backup-dump.html) and
[selective restore](https://www.postgresql.org/docs/16/app-pgrestore.html).

There is no cross-datastore synchronization in this supplied write path. The application still
owns embedding generation and updates when source text changes. Index maintenance and rebuilding
remain possible; pgvector explicitly documents
[reindexing](https://github.com/pgvector/pgvector/blob/v0.8.6/README.md#vacuuming).

## Qdrant

**Not installed, not deployed, and not required by this Task.** Do not try to run it. The
comparison is a reading exercise; the profile is what the checks grade.

The [Qdrant v1.15.0 API specification](https://github.com/qdrant/qdrant/blob/v1.15.0/docs/redoc/master/openapi.json)
is the versioned reading reference for collections, points, payloads, and filtered queries.
The linked vendor concept pages were reviewed on 2026-09-08 and can change or discuss later
releases. This documentation reference is not a deployment pin or an observed runtime result.

**Storage and layout.** Qdrant organizes data into *collections* of *points* with vector data and
optional JSON payloads. A point can hold named vectors, so the model is not limited to one vector
per point. The entity database remains separate under this profile's declared assumptions. See
[collections](https://qdrant.tech/documentation/manage-data/collections/),
[points](https://qdrant.tech/documentation/manage-data/points/), and
[payloads](https://qdrant.tech/documentation/manage-data/payload/).

**Filtering.** One vector-search request can carry conditions on payload fields. Qdrant uses
payload indexes and filter cardinality estimates to choose a search strategy; the filter does not
prescribe one fixed traversal order. See [filtering](https://qdrant.tech/documentation/search/filtering/)
and [payload indexing](https://qdrant.tech/documentation/manage-data/indexing/#payload-index).

**Operational footprint.** A second service alongside the entity database: its own cluster, its own
snapshot and restore lifecycle, and a synchronization path to keep its points consistent with the
source of truth. This second service follows from the declared architecture; it is not a claim
that every Qdrant deployment must have a separate entity database.

**Backup, restore, and synchronization.** A collection snapshot contains Qdrant collection data
on the node where it is taken. Distributed deployments need the appropriate per-node recovery
procedure. It does not back up the external entity database; recovery must coordinate or reconcile
the two saved states. See [Qdrant snapshots](https://qdrant.tech/documentation/operations/snapshots/).

The application or ingestion pipeline must propagate source changes affecting indexed vectors or
payloads, including relevant deletions, and detect and repair divergence after partial failures or
rebuilding. Unrelated source writes need no collection update. This is an operational implication
of the declared separate-store architecture, not a measured property of a Qdrant installation.

## What this comparison does not claim

- No performance, scale, recall, or cost figure. None was measured, and this corpus of 18 documents
  could not support one.
- No preference. Both layouts are legitimate; which one fits depends on volume, team, and
  operational appetite, and this Task grades neither a recommendation nor an opinion.
- The Qdrant rows describe a documented data model, not an observation of a running cluster.
- The source review verifies the supplied profile facts and accepted answers for the local release.
  Additional CME sign-off remains deferred; `qualification.confirmed_by_cme: false` records that
  unperformed review honestly. No Qdrant runtime qualification is claimed.
