# Supplied retrieval corpus

## Provenance

Every document, provenance entry, and query in this directory was written for this curriculum.
There is no external source, no scraped page, no customer document, and no real shipping
procedure among them. Coldline, Northwind Cold Chain, and Baltic Reefer Lines are fictional
organizations, and every temperature, window, and reference in the text is invented for teaching.

| File | What it holds |
|---|---|
| `documents.jsonl` | 18 whole documents with a title, a body, an access label, and a provenance record |
| `provenance.jsonl` | one custody entry per document, cross-checked during ingestion |
| `queries.jsonl` | 11 published queries, each naming the document its answer must come from |

## Synthetic

The corpus is **synthetic**. It contains no personal data, no credential, no production record,
and nothing confidential. It is small on purpose: 18 documents across three tenancies make the
dense arm, the sparse arm, and candidate fusion inspectable by reading a report rather than by
sampling a large index. `tests/contract/test_retrieval_contract.py` pins both counts, so a fixture
that grows or shrinks without this page being updated fails a check rather than drifting.

Do not add real operational content, customer data, or credentials to this directory.

## Licence

Licence: TripleTen curriculum content, written for this Task and distributed with the Task
repository. The `license` field on every `provenance.jsonl` entry records the same statement in
machine-readable form, so a check can confirm the record exists rather than trusting this page.

## How the relevance labels are derived

`queries.jsonl` carries no hand-scored passage judgements. Each query names one
`target_document_id`, and the binary relevance label follows *structurally*:

```text
relevant(chunk, query)  <=>  chunk.document_id == query.target_document_id
```

That derivation is the whole labelling rule. It cannot drift away from the corpus, and a reviewer
can re-derive every label from these two files alone. The published outcome criteria in
`tests/golden.py` build on it:

| Criterion | Definition |
|---|---|
| success | the query's target document appears in the final ranked results |
| miss | the query's target document appears nowhere in the final ranked results |

## Format note

These files are JSON Lines: one JSON object per line, no comments. JSON has no comment syntax, so
the explanation lives here instead of inside the fixtures. The ingestion loader validates every
line against the domain contracts and fails the run rather than importing a malformed record.
