# Cached judge evidence

`cached-judgements.jsonl` holds the comparison-only evaluation this Task compares against the
deterministic metrics. It is a **cached** artifact: nothing in this repository calls a model
service, and no test may.

## Synthetic

Every judgement is synthetic. It was produced by a recorded heuristic over the synthetic corpus in
`infra/corpus/`, not by a language model, not by a human rater, and not from any real Coldline
system. It carries no personal data and no customer content.

The judge identifier in every record is `coldline-cached-heuristic-v1`. That name is deliberate:
this is a *stand-in* for a model-based evaluator, so a local run can show two evaluation signals
diverging without a billable API call. It makes no claim about how a production judge model would
score these passages.

## Licence

Same terms as the rest of this repository. The corpus it derives from is synthetic and
TripleTen-owned; see `infra/corpus/README.md`.

## Provenance

Derived deterministically from the two committed fixtures `infra/corpus/documents.jsonl` and
`infra/corpus/queries.jsonl`, recorded once at `judged_at`, and never regenerated during a run. A
reviewer can re-derive every line from those two files alone:

1. Split each document body into 28-word, non-overlapping chunks, exactly as `domain/chunking.py`
   does, and identify chunk `i` of document `d` as `d#0000`-style, zero-padded to four digits.
2. Form each chunk's judged text as its document `title`, a single space, then the chunk text.
3. Tokenize a text by lowercasing it, splitting on every run of characters outside `a-z0-9`,
   discarding tokens shorter than 4 characters, and discarding these stop words:
   `been does each from have must that then this when with`.
4. For each published query, judge every chunk whose `tenant_id` equals the query's `tenant_id` —
   the deployed authorization policy restricts retrieval to the caller's own tenancy, so a chunk
   outside it can never be retrieved and is never judged.
5. With `Q` the query's token set and `C` the chunk's token set:
   - `relevance = round(|Q ∩ C| / |Q|, 3)`
   - `faithfulness = round(|Q ∩ C| / |C|, 3)`

## What each field means, and which one is compared

| Field | Meaning |
|---|---|
| `query_id` | The published query this judgement is about |
| `chunk_id` | The chunk being judged |
| `relevance` | How much of the question this chunk covers. **This is the signal the comparison uses.** |
| `faithfulness` | How much of this chunk is about the question. Recorded evidence; `poe compare` prints it, and no automated check grades it. |
| `judge` | The evaluator identity |
| `judged_at` | When the judgement was cached |

## Limits

This evidence is comparison-only and is never authoritative. The deterministic Recall@K computed
against the published binary labels in `tests/golden.py` is the authoritative quality metric for
this Task. The two measure different things — coverage of the labelled relevant material versus
per-passage contextual overlap — and they are expected to disagree under some configurations.
That disagreement is a finding to classify, not a defect to fix.
