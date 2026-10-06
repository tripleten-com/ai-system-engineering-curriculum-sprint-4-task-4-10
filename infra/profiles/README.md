# Supplied technical profiles

## Provenance

The two profiles in this directory are the graded source for three of Task 2.8's answers. They
were written for this curriculum. Nothing here was scraped, and nothing here is a vendor
statement quoted verbatim.

| File | What it holds |
|---|---|
| `vector-engines.yaml` | Storage layout, filtering mechanism, and operational footprint for PostgreSQL with pgvector and for Qdrant |
| `object-store-fidelity.yaml` | Published credential-validation evidence, an ungraded pagination coverage gap, and explicit local-release limits |

The `pgvector` rows are derived from this repository itself: the `embedding vector(64)` column in
`infra/postgres/002_retrieval_corpus.sql` and the query built in
`src/adapters/retriever/postgres_hybrid.py`. A reviewer can check them against the code.

The `qdrant` rows describe its documented data model — collections of points, each carrying a
vector and a JSON payload — and were **not** observed in a running system. Qdrant is not
installed, not deployed, and not required by this Task.

## Synthetic

These are teaching profiles. They carry no measurement, no benchmark, no customer configuration,
and no credential.

## Licence

Licence: TripleTen curriculum content, written for this Task and distributed with the Task
repository.

## Why the answers are graded against a file

Task 2.8 asks for a factual classification, and a factual question has to be answerable from
something the Task supplied. Grading a classification against world knowledge would mean grading a
student on material this repository never gave them, and would silently drift as products change.
The checks therefore read `vector-engines.yaml` and `object-store-fidelity.yaml`.

The prose in [`docs/architecture/vector-engines.md`](../../docs/architecture/vector-engines.md) and
[`docs/fidelity/ObjectStore.md`](../../docs/fidelity/ObjectStore.md) says the same things at
length, for reading. If prose and profile ever disagree, the profile is what the checks read, and
the disagreement is a defect in the Task rather than in a submission.

## What these profiles do not support

No performance, scale, recall, or cost claim. No recommendation. Both storage layouts are
legitimate engineering choices, and this Task asks only which layout each engine implements and
which published fidelity limitation this profile documents. The pagination coverage gap is not
evidence of a LocalStack/AWS behavioral divergence and is excluded from the answer enum. Its
observation remains documented as an ungraded limit on the evidence.
