# Retriever fidelity

The active adapter is `src/adapters/retriever/postgres_hybrid.py`. It runs four observable stages
against PostgreSQL 16 with the `pgvector` extension and PostgreSQL full-text search:

```text
authorization -> dense (pgvector cosine)  \
              -> sparse (OR of query lexemes + ts_rank_cd) -> weighted RRF fusion -> top_k
```

## What the local runtime proves

- Both arms run as real SQL against real indexes, and fusion combines two genuinely different
  rankings. The runtime contract fails if either arm returns nothing or if both return the same
  candidate set for the check query.
- Determinism. The same corpus, query, `top_k`, and `dense_weight` produce the same ranking on
  every run and in every process: embeddings are hashed with `blake2b` rather than Python's
  per-process-salted `hash()`, ordering breaks ties on `chunk_id`, and the dense arm uses exact
  nearest-neighbour ordering with no approximate index.
- Per-stage evidence. Each stage records the identifiers it admitted and, for fusion, the ones it
  dropped. That evidence is what a Task 2.8 attribution rests on.
- The authorization constraint is applied *inside* both arm queries as parameterized predicates,
  so an out-of-scope row is never fetched and then filtered in memory.

## What the local runtime does not prove

| Not proven | Why |
|---|---|
| Semantic retrieval quality | The embedding is a hashed bag of tokens with 64 dimensions. It is a controlled algorithmic stand-in for a hosted embedding model. It captures token overlap, not paraphrase, synonymy, or word order, and no statement about production retrieval quality follows from any score it produces. |
| Index performance or scaling | Exact search over a 12-document corpus says nothing about approximate-index recall, build time, or memory at production volume. |
| Authenticated authorization | The caller states its own tenancy and clearance in the request body. This local system has no authentication, so the authorization context is an *asserted* identity, not a verified one. Enforcing a constraint against an asserted identity proves the retrieval boundary, not an access-control system. |
| Managed database behavior | Nothing here establishes managed-RDS availability, backup, failover, or connection-limit behavior. |

## Enforcement state by Task

`RetrievalResult.authorization_enforced` reports whether the applied constraint actually restricted
anything. The adapter derives it from the constraint it used, never from a policy object's claim
about itself.

| Checkpoint | Composed policy | `authorization_enforced` |
|---|---|---|
| Task 2.1 through Task 2.3 | `UnrestrictedAccessConstraints` | `false` — the context is carried and recorded but nothing is filtered, and a caller can retrieve another tenancy's chunk |
| Task 2.4 starter | `UnrestrictedAccessConstraints`, now composed through `build_access_constraints` | `false` — this is the state the Task asks you to change |
| Task 2.4 completed, and Task 2.5 onward | one student dimension plus the supplied complement; both dimensions enforced | `true` — the adapter derives this from the constraint it applied |

The Task 2.1 state is asserted by a runtime contract rather than left implicit, so enforcement
cannot arrive early by accident and the Task 2.4 change is observable.

### What enforcement here does not establish

The constraint is applied inside both query arms, so an out-of-scope row is never fetched. That is
a real retrieval boundary and the checks read the per-stage evidence to confirm it.

It is still not an access-control system. The caller states its own tenancy and clearance in the
request body, and this local system has no authentication to check that claim against. Enforcing
a constraint derived from an asserted identity proves the retrieval boundary works; it proves
nothing about identity, session handling, token validation, or privilege escalation.

## The worker as a second caller (Project 4)

From the Project 4 opening checkpoint the worker also calls the port, from its own process and
its own connection pool, to find the procedure that matches one excursion
(`src/worker/procedures.py`). It is not a caller with a tenancy of its own: it runs every lookup
under one fixed service scope, the procedure tenancy with the restricted clearance, composed with
the tenant-boundary constraint only, so it reads every tier of that tenancy. The best-ranked
chunk becomes a bounded excerpt in the model request. Nothing about the adapter changes for this
caller; what changes is that corpus text written by whoever publishes procedures now reaches the
model provider with every matching exception.
