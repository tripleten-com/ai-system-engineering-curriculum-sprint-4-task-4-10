"""Coldline.

===================

File:              tests/doubles/retrieval.py
Component:         Test doubles — Retrieval
Purpose:           Supply deterministic stand-ins for the Retriever port and both services.
Interacts With:    The service contracts, contract tests, and student tests
Sprint/Task:       Sprint 2 — Project 2
Concepts:          Independent execution, substitutability, determinism
Tools:             Python 3.12
"""

from domain.contracts import (
    AccessLabel,
    AccessTier,
    AssembledContext,
    AuthorizationContext,
    Candidate,
    RetrievalRequest,
    RetrievalResult,
    RetrievalStage,
    StageEvidence,
)
from domain.services import OrchestratedRetrieval
from ports import Retriever

FIXTURE_TENANT = "tenant-double"


def candidate(
    chunk_id: str,
    rank: int,
    *,
    text: str | None = None,
    tenant_id: str = FIXTURE_TENANT,
    access_tier: AccessTier = AccessTier.STANDARD,
    revision: str = "r1",
) -> Candidate:
    """Return one ranked candidate with a derived document identifier.

    ``chunk_id`` follows the real ``<document_id>#<index>`` shape, so a double
    exercises the same identity rules the running system does.
    """
    return Candidate(
        chunk_id=chunk_id,
        document_id=chunk_id.split("#", maxsplit=1)[0],
        rank=rank,
        score=1.0 / rank,
        text=text if text is not None else f"text for {chunk_id}",
        access=AccessLabel(tenant_id=tenant_id, access_tier=access_tier),
        provenance_revision=revision,
    )


def stub_result(
    query_id: str, candidates: tuple[Candidate, ...], *, explained: bool = False
) -> RetrievalResult:
    """Return one deterministic retrieval result with plausible stage evidence."""
    identifiers = tuple(item.chunk_id for item in candidates)
    return RetrievalResult(
        query_id=query_id,
        results=candidates,
        stages=(
            StageEvidence(
                stage=RetrievalStage.AUTHORIZATION,
                admitted=identifiers if explained else (),
                note="double: no constraint applied",
            ),
            StageEvidence(stage=RetrievalStage.DENSE, admitted=identifiers),
            StageEvidence(stage=RetrievalStage.SPARSE, admitted=identifiers),
            StageEvidence(stage=RetrievalStage.FUSION, admitted=identifiers),
        ),
        authorization_enforced=False,
    )


class StubRetriever:
    """Return a fixed ranking without a database, a network, or an index.

    The double records every request it receives, which is how a test proves
    that an orchestration implementation built the request from the caller's
    identity and the configured parameters instead of hard-coding them.
    """

    def __init__(self, candidates: tuple[Candidate, ...]) -> None:
        """Bind the double to the ranking it always returns."""
        self._candidates = candidates
        self.requests: list[RetrievalRequest] = []

    async def search_hybrid(self, request: RetrievalRequest) -> RetrievalResult:
        """Return the fixed ranking truncated to the requested `top_k`."""
        self.requests.append(request)
        return stub_result(
            request.query_id,
            tuple(
                item.model_copy(update={"rank": rank})
                for rank, item in enumerate(self._candidates[: request.top_k], start=1)
            ),
            explained=request.explain,
        )


class AlternativeRetrievalOrchestrator:
    """Select candidates in reverse fused order.

    This is the *substitution* implementation. It satisfies the same contract
    shape and deliberately produces a different selection, so swapping it into
    the workflow must change the workflow's output without any caller edit. It
    is not a model answer: reverse order is not a sensible policy.
    """

    def __init__(
        self, retriever: Retriever, *, top_k: int, dense_weight: float, citation_limit: int
    ) -> None:
        """Bind the alternative to the same collaborators the real service receives."""
        self._retriever = retriever
        self._top_k = top_k
        self._dense_weight = dense_weight
        self._citation_limit = citation_limit

    async def orchestrate(
        self,
        query_id: str,
        text: str,
        authorization: AuthorizationContext,
        *,
        explain: bool = False,
    ) -> OrchestratedRetrieval:
        """Return the retriever answer with the selection reversed."""
        request = RetrievalRequest(
            query_id=query_id,
            text=text,
            authorization=authorization,
            top_k=self._top_k,
            dense_weight=self._dense_weight,
            explain=explain,
        )
        # The double accepts any object with the port operation so a test can
        # pass either the stub or the real adapter.
        result: RetrievalResult = await self._retriever.search_hybrid(request)
        selected: list[Candidate] = []
        seen: set[str] = set()
        for item in reversed(result.results):
            if item.document_id in seen:
                continue
            seen.add(item.document_id)
            selected.append(item)
            if len(selected) == self._citation_limit:
                break
        return OrchestratedRetrieval(result=result, selected=tuple(selected))


class AlternativeContextAssembler:
    """Emit one block per candidate with the text replaced by its length.

    This is the *substitution* implementation for the assembly choice. It obeys
    the budget and the citation format but deliberately produces different
    prompt text, so a swap is observable without a caller edit.
    """

    def __init__(self, *, token_budget: int, citation_limit: int) -> None:
        """Bind the alternative to the same parameters the real service receives."""
        self._token_budget = token_budget
        self._citation_limit = citation_limit

    def assemble(self, query_id: str, selected: tuple[Candidate, ...]) -> AssembledContext:
        """Return a length-only context that still respects the declared budget."""
        blocks = [f"[{item.chunk_id}] {len(item.text.split())}" for item in selected]
        used = min(len(blocks), self._token_budget)
        return AssembledContext(
            query_id=query_id,
            prompt_context="\n\n".join(blocks),
            citations=tuple(
                f"{item.document_id}@{item.provenance_revision}"
                f" ({item.access.tenant_id}/{item.access.access_tier.value})"
                for item in selected
            ),
            token_budget=self._token_budget,
            used_tokens=used,
        )
