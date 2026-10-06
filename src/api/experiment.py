"""Coldline.

===================

File:              src/api/experiment.py
Component:         API — Retrieval evaluation surface
Purpose:           Run one retrieval query under explicitly stated parameters.
Interacts With:    The Retriever port and domain contracts
Sprint/Task:       Sprint 2 — Project 2 / Task 2.7
Concepts:          Controlled measurement, evaluation surfaces
Tools:             Python 3.12

Supplied and protected. This is an *evaluation* surface, not a product one.

Task 2.7 compares two retrieval configurations. Comparing them by restarting
the service between arms would put a cold connection pool and an unwarmed
database cache on one side of the comparison and not the other, so the
controlled parameters are stated per request instead and both arms run against
one already-running system.

The product endpoint `POST /api/v1/retrieval/search` keeps its own composed
defaults and takes no parameters from callers; tuning knobs do not belong on a
product API. What this surface returns is the same quantity that endpoint
reports in its `results` field - the retriever's fused ranking - so a metric
measured here is a metric about the deployed retrieval path.
"""

from adapters.retriever.postgres_hybrid import CANDIDATE_POOL
from domain.contracts import AuthorizationContext, RetrievalRequest, RetrievalResult
from ports import Retriever

# Each arm fetches this many candidates before fusion, so a larger `top_k`
# could never be satisfied and is rejected at the HTTP boundary instead of
# quietly returning fewer results than the caller asked to measure.
TOP_K_LIMIT = CANDIDATE_POOL


class ExperimentRetrieval:
    """Retrieve under caller-stated parameters for evaluation purposes only."""

    def __init__(self, retriever: Retriever) -> None:
        """Receive the retrieval port this surface measures."""
        self._retriever = retriever

    async def measure(
        self,
        query_id: str,
        text: str,
        authorization: AuthorizationContext,
        *,
        top_k: int,
        fusion_weight: float,
    ) -> RetrievalResult:
        """Return the fused ranking one configuration produces for one query.

        No prompt context is assembled. The metrics this Task records are about
        what retrieval returned, and assembling a context the caller discards
        would add work to every latency sample without adding evidence.
        """
        return await self._retriever.search_hybrid(
            RetrievalRequest(
                query_id=query_id,
                text=text,
                authorization=authorization,
                top_k=top_k,
                # `fusion_weight` is this Task's name for the weight the dense
                # arm carries in reciprocal-rank fusion, which the retrieval
                # contract calls `dense_weight`.
                dense_weight=fusion_weight,
                explain=False,
            )
        )
