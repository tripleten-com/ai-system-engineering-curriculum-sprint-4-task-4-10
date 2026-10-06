# Supplied retrieval pipeline

This page is a reference for the supplied code. Your Task lesson decides what to do; this page
says what the pipeline is and where each part lives.

## Stages

```text
                        +------------------------------+
query text + caller --> | authorization                |  resolve one AccessConstraint
                        | domain/access.py             |  from the caller context
                        +---------------+--------------+
                                        |  constraint applied INSIDE both queries below
                        +---------------v--------------+
                        | dense arm (pgvector)         |  embedding <=> query vector
                        | sparse arm (full-text)       |  OR of lexemes + ts_rank_cd
                        +---------------+--------------+
                                        |  two ranked candidate lists
                        +---------------v--------------+
                        | fusion  domain/fusion.py     |  weighted reciprocal rank
                        +---------------+--------------+
                                        |  top_k candidates + per-stage evidence
                        +---------------v--------------+
                        | retrieval orchestration      |  dedupe by document, cap at citation limit
                        | api/retrieval_workflow.py    |
                        +---------------+--------------+
                                        |  selected candidates
                        +---------------v--------------+
                        | context assembly             |  trim to token budget, format, cite
                        | api/retrieval_workflow.py    |
                        +------------------------------+
```

## Where each part lives

| Part | Path | Owner |
|---|---|---|
| Deterministic embedding | `src/domain/embedding.py` | supplied |
| Deterministic chunking | `src/domain/chunking.py` | supplied |
| Candidate fusion | `src/domain/fusion.py` | supplied |
| Access-constraint contract and the unrestricted policy | `src/domain/access.py` | supplied |
| Dense, sparse, authorization, and fusion execution | `src/adapters/retriever/postgres_hybrid.py` | supplied, protected |
| Baseline corpus ingestion | `src/adapters/persistence/corpus_loader.py` | supplied, protected |
| Object-storage access | `src/adapters/object_store/s3.py` | supplied, protected |
| Coupled orchestration and context assembly | `src/api/retrieval_workflow.py` | supplied |
| Corpus, custody record, and published query set | `infra/corpus/` | supplied |
| Document and chunk schema | `infra/postgres/002_retrieval_corpus.sql` | supplied, protected |

## Controlled parameters

Two parameters change the outcome. Everything else about the pipeline is fixed.

| Parameter | Meaning | Supplied default |
|---|---|---:|
| `top_k` | how many fused candidates the final result keeps | 3 |
| `dense_weight` | the weight given to the dense arm in fusion; the sparse arm receives `1 - dense_weight` | 0.5 |

Each arm returns a fixed candidate pool of 12 rows *before* fusion. That is deliberate: changing
`top_k` changes what fusion selects without also changing what the arms see, so tuning `top_k` is
a single-variable change.

## What each arm actually runs

| Arm | Query | Ordering |
|---|---|---|
| dense | `embedding <=> $query_vector` over `vector(64)` | exact cosine distance, ties on `chunk_id` |
| sparse | the **OR** of the query lexemes against the stored `tsvector` | `ts_rank_cd` descending, ties on `chunk_id` |

The sparse arm ORs its lexemes on purpose. `websearch_to_tsquery` and `plainto_tsquery` both AND
their terms, so a multi-word question matches almost nothing and the sparse arm contributes
nothing. Keyword retrieval is supposed to return partial matches and let the ranking sort them
out. A query with no indexable lexemes returns no rows rather than failing.

## Reading the stage evidence

Every response carries one entry per stage under `stages`.

| Field | Meaning |
|---|---|
| `admitted` | the identifiers that stage produced, in the order it produced them |
| `dropped` | the identifiers that stage removed (fusion reports the candidates that reached it but did not make `top_k`) |
| `note` | a short, bounded description of what the stage did |

Two consequences are worth stating plainly:

- A chunk listed by `dense` or `sparse` **was** read from the database and **did** reach fusion.
  The authorization constraint admitted it, because both arms carry that constraint.
- The `authorization` stage lists its readable pool only when a request sets `explain`, because
  listing it costs one extra query. Ordinary requests and the benchmark harness leave it off so no
  diagnostic query enters a measured path.

## Attribution rules

When a query misses, the stage evidence decides which stage is responsible. These rules are
published so an attribution is a reading of evidence rather than an opinion:

| Evidence about the target chunk | Responsible stage |
|---|---|
| absent from the readable pool the `authorization` stage reports | `authorization_filtering` |
| the answer text is split across two chunks, so no single chunk contains it | `chunking` |
| present in `sparse` but absent from `dense`, and the answer text is intact in one chunk | `embedding` |
| present in `dense` but absent from `sparse`, and its terms are present in the chunk text | `sparse_matching` |
| present in **both** `dense` and `sparse`, yet absent from the final results | `fusion` |

Read them in order and stop at the first that matches the evidence. A stage "operated normally"
for a target chunk when it admitted that chunk; a stage that dropped the target chunk did not.

## Object-storage boundary

`infra/corpus/documents.jsonl` and `infra/corpus/provenance.jsonl` ship in the repository, and the
initializer uploads them into the LocalStack bucket. Ingestion then reads them **back** through the
`ObjectStore` port. Nothing outside `src/adapters/object_store/` imports a cloud SDK, and both the
authoring integrity check and a public contract test fail if that changes.

See [ObjectStore fidelity](../fidelity/ObjectStore.md) and
[Retriever fidelity](../fidelity/Retriever.md) for what this local runtime does and does not
establish.
