"""Coldline.

===================

File:              src/adapters/retriever/postgres_hybrid.py
Component:         Adapter — PostgreSQL hybrid retriever
Purpose:           Implement dense, sparse, authorization, and fusion retrieval stages.
Interacts With:    PostgreSQL with pgvector, domain fusion and access contracts
Sprint/Task:       Sprint 2 — Project 2
Concepts:          Hybrid retrieval, query-time authorization, stage evidence
Tools:             Python 3.12, PostgreSQL, pgvector, PostgreSQL full-text search
"""

from typing import Any

import asyncpg
from opentelemetry import trace

from domain.access import AccessConstraint, AccessConstraintProvider
from domain.contracts import (
    AccessLabel,
    AccessTier,
    Candidate,
    RetrievalRequest,
    RetrievalResult,
    RetrievalStage,
    StageEvidence,
)
from domain.embedding import embed, format_vector
from domain.failures import RetrievalUnavailable
from domain.fusion import fuse

_TRACER = trace.get_tracer(__name__)

# Rows each arm returns before fusion. Each arm returns a fixed pool rather
# than top_k rows so that changing top_k changes what fusion *selects* without
# also changing what the arms *see*; a Task 2.7 experiment on top_k is
# therefore a single-variable change.
CANDIDATE_POOL = 12


class PostgresHybridRetriever:
    """Run the supplied hybrid retrieval pipeline against PostgreSQL.

    Stages, in execution order:

    ```text
    authorization -> [dense (pgvector) + sparse (full-text)] -> fusion -> top_k
    ```

    The authorization constraint is resolved first and then applied *inside*
    both arm queries as parameterized predicates, so an out-of-scope chunk is
    never fetched and cannot be dropped later by a caller. The constraint
    itself is provided by an ``AccessConstraintProvider``; this adapter does
    not decide policy.

    Every stage records the identifiers it produced. That evidence is the basis
    for a Task 2.8 attribution: a chunk listed by ``dense`` or ``sparse``
    reached fusion, and a chunk absent from the final results but present in
    both arms was ranked out by fusion.
    """

    def __init__(
        self,
        pool: asyncpg.Pool,
        *,
        access_constraints: AccessConstraintProvider,
        candidate_pool: int = CANDIDATE_POOL,
    ) -> None:
        """Bind the adapter to a pool and the composed access-constraint policy."""
        if not isinstance(candidate_pool, int) or isinstance(candidate_pool, bool):
            raise TypeError("candidate_pool must be an integer")
        if candidate_pool < 1:
            raise ValueError("candidate_pool must be at least 1")
        self._pool = pool
        self._access_constraints = access_constraints
        self._candidate_pool = candidate_pool

    async def search_hybrid(self, request: RetrievalRequest) -> RetrievalResult:
        """Return the fused ranking and per-stage evidence for one request."""
        with _TRACER.start_as_current_span(
            "retriever.search_hybrid",
            attributes={
                "coldline.query_id": request.query_id,
                "coldline.top_k": request.top_k,
            },
        ):
            constraint = self._access_constraints.constrain(request.authorization)
            # Both arms bind one leading parameter of their own, so their
            # constraint placeholders start at $2. The pool query binds none.
            clause, parameters = _constraint_clause(constraint, first_placeholder=2)
            stages: list[StageEvidence] = [await self._authorization_evidence(request, constraint)]
            try:
                dense = await self._dense(request, clause, parameters)
                sparse = await self._sparse(request, clause, parameters)
            except asyncpg.PostgresError as exc:
                raise RetrievalUnavailable("retrieval backend rejected the query") from exc
            except OSError as exc:
                raise RetrievalUnavailable("retrieval backend is unreachable") from exc

            stages.append(
                StageEvidence(
                    stage=RetrievalStage.DENSE,
                    admitted=tuple(candidate.chunk_id for candidate in dense),
                    note=f"pgvector cosine distance over {len(dense)} candidates",
                )
            )
            stages.append(
                StageEvidence(
                    stage=RetrievalStage.SPARSE,
                    admitted=tuple(candidate.chunk_id for candidate in sparse),
                    note=f"full-text rank over {len(sparse)} candidates",
                )
            )

            fused = fuse(dense, sparse, dense_weight=request.dense_weight, limit=request.top_k)
            reached_fusion = {candidate.chunk_id for candidate in dense} | {
                candidate.chunk_id for candidate in sparse
            }
            selected = {candidate.chunk_id for candidate in fused}
            stages.append(
                StageEvidence(
                    stage=RetrievalStage.FUSION,
                    admitted=tuple(candidate.chunk_id for candidate in fused),
                    dropped=tuple(sorted(reached_fusion - selected)),
                    note=(
                        f"weighted reciprocal rank, dense_weight={request.dense_weight}, "
                        f"top_k={request.top_k}"
                    ),
                )
            )
            return RetrievalResult(
                query_id=request.query_id,
                results=tuple(fused),
                stages=tuple(stages),
                authorization_enforced=constraint.restricts,
            )

    async def _authorization_evidence(
        self, request: RetrievalRequest, constraint: AccessConstraint
    ) -> StageEvidence:
        """Record what the authorization stage decided for this caller.

        ``admitted`` is filled only when the request asks for it, because
        listing the readable pool costs one extra query. It never lists an
        out-of-scope identifier: the pool query carries the same constraint as
        both arms, so unauthorized content is not read here either.
        """
        note = (
            f"constraint applied inside both arms; "
            f"tenant_ids={_describe(constraint.tenant_ids)}; "
            f"access_tiers={_describe(constraint.access_tiers)}"
        )
        if not request.explain:
            return StageEvidence(stage=RetrievalStage.AUTHORIZATION, admitted=(), note=note)
        clause, parameters = _constraint_clause(constraint, first_placeholder=1)
        try:
            rows = await self._pool.fetch(
                f"SELECT chunk_id FROM chunks WHERE {clause} ORDER BY chunk_id",  # noqa: S608
                *parameters,
            )
        except asyncpg.PostgresError as exc:
            raise RetrievalUnavailable("retrieval backend rejected the pool query") from exc
        return StageEvidence(
            stage=RetrievalStage.AUTHORIZATION,
            admitted=tuple(row["chunk_id"] for row in rows),
            note=f"{note}; readable pool {len(rows)} chunks",
        )

    async def _dense(
        self, request: RetrievalRequest, clause: str, parameters: list[Any]
    ) -> list[Candidate]:
        """Return the dense arm's ranked candidates from pgvector."""
        vector = format_vector(embed(request.text))
        # Exact nearest-neighbour ordering. The corpus is small and the ranking
        # must be identical on every run, so no approximate index is used and
        # no production index-tuning claim follows from this query.
        rows = await self._pool.fetch(
            f"""
            SELECT chunk_id,
                   document_id,
                   chunk_text,
                   tenant_id,
                   access_tier,
                   provenance_revision,
                   1 - (embedding <=> $1::vector) AS score
            FROM chunks
            WHERE {clause}
            ORDER BY embedding <=> $1::vector, chunk_id
            LIMIT {self._candidate_pool}
            """,  # noqa: S608
            vector,
            *parameters,
        )
        return _candidates(rows)

    async def _sparse(
        self, request: RetrievalRequest, clause: str, parameters: list[Any]
    ) -> list[Candidate]:
        """Return the sparse arm's ranked candidates from PostgreSQL text search.

        The query is the OR of the query lexemes, ranked by ``ts_rank_cd``.
        ``websearch_to_tsquery`` and ``plainto_tsquery`` both AND their terms,
        which makes a multi-word question match almost nothing and turns the
        sparse arm into dead weight. Keyword retrieval is supposed to return
        partial matches and let the ranking sort them out, so the lexemes are
        combined with ``|`` and the ranking does the discriminating.

        A query with no indexable lexemes (punctuation only) yields a NULL
        query and therefore no rows, rather than a SQL syntax error.
        """
        rows = await self._pool.fetch(
            f"""
            WITH parsed AS (
                SELECT to_tsquery(
                    'english',
                    NULLIF(
                        array_to_string(
                            tsvector_to_array(to_tsvector('english', $1)), ' | '
                        ),
                        ''
                    )
                ) AS query
            )
            SELECT chunk_id,
                   document_id,
                   chunk_text,
                   tenant_id,
                   access_tier,
                   provenance_revision,
                   ts_rank_cd(search_document, parsed.query) AS score
            FROM chunks, parsed
            WHERE parsed.query IS NOT NULL
              AND search_document @@ parsed.query
              AND {clause}
            ORDER BY score DESC, chunk_id
            LIMIT {self._candidate_pool}
            """,  # noqa: S608
            request.text,
            *parameters,
        )
        return _candidates(rows)


def _candidates(rows: list[asyncpg.Record]) -> list[Candidate]:
    """Convert ranked rows into provider-neutral candidates."""
    return [
        Candidate(
            chunk_id=row["chunk_id"],
            document_id=row["document_id"],
            rank=position,
            score=float(row["score"]),
            text=row["chunk_text"],
            access=AccessLabel(
                tenant_id=row["tenant_id"],
                access_tier=AccessTier(row["access_tier"]),
            ),
            provenance_revision=row["provenance_revision"],
        )
        for position, row in enumerate(rows, start=1)
    ]


def _constraint_clause(
    constraint: AccessConstraint, *, first_placeholder: int
) -> tuple[str, list[Any]]:
    """Translate a declarative access constraint into a parameterized predicate.

    Only placeholders are emitted; no caller value is ever formatted into SQL
    text. An empty allowed set becomes ``false`` rather than a clause that
    silently matches everything, so a policy that denies everything really
    denies everything and is visible in the results.
    """
    tiers = (
        None
        if constraint.access_tiers is None
        else [tier.value for tier in constraint.access_tiers]
    )
    dimensions: list[tuple[str, list[str] | None]] = [
        ("tenant_id", None if constraint.tenant_ids is None else list(constraint.tenant_ids)),
        ("access_tier", tiers),
    ]
    conditions: list[str] = []
    parameters: list[Any] = []
    placeholder = first_placeholder
    for column, values in dimensions:
        if values is None:
            continue
        if not values:
            conditions.append("false")
            continue
        conditions.append(f"{column} = ANY(${placeholder}::text[])")
        parameters.append(values)
        placeholder += 1
    return (" AND ".join(conditions) if conditions else "true"), parameters


def _describe(values: tuple[str, ...] | tuple[AccessTier, ...] | None) -> str:
    """Return a bounded, printable description of one constraint dimension."""
    if values is None:
        return "unrestricted"
    if not values:
        return "none"
    return ",".join(sorted(str(value) for value in values))
