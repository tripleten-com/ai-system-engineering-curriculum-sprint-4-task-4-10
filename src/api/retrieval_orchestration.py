"""Coldline.

===================

File:              src/api/retrieval_orchestration.py
Component:         Domain — Retrieval orchestration
Purpose:           Coordinate one retrieval request and select the candidates to carry forward.
Interacts With:    The Retriever port, domain contracts, and the retrieval workflow
Sprint/Task:       Sprint 2 — Project 2
Concepts:          Responsibility boundaries, dependency inversion
Tools:             Python 3.12

This is the reference service boundary from Task 2.2, now supplied and
protected. Task 2.2 asked a student to extract one of two responsibilities;
ADR-008 (ADR008-R09) makes retrieval orchestration the single
documented reference choice so that every later Task starts from one
deterministic state. A student's own Task 2.2 implementation stays in that
Task's pull request and is never required to match this file.

The class was named `StudentRetrievalOrchestrator` while it was student work.
It is renamed here because it is no longer student work, and it moves out of
`api/extensions/` for the same reason: that package is the per-Task student
surface. It stays in the application layer because it depends on the
`Retriever` port, and `domain` may not import outward.
"""

from domain.contracts import AuthorizationContext, Candidate, RetrievalRequest
from domain.services import OrchestratedRetrieval
from ports import Retriever


class RetrievalOrchestrationService:
    """Coordinate retrieval and choose which candidates travel downstream.

    The boundary is visible in the imports: this module depends on the
    ``Retriever`` port and on domain contracts, and on nothing else. It has no
    database driver, no cloud SDK, and no import of the application that calls
    it.
    """

    def __init__(
        self,
        retriever: Retriever,
        *,
        top_k: int,
        dense_weight: float,
        citation_limit: int,
    ) -> None:
        """Receive the retrieval port and the controlled retrieval parameters."""
        if citation_limit < 1:
            raise ValueError("citation_limit must be at least 1")
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
        """Return the retriever answer and the candidates selected from it."""
        request = RetrievalRequest(
            query_id=query_id,
            text=text,
            authorization=authorization,
            top_k=self._top_k,
            dense_weight=self._dense_weight,
            explain=explain,
        )
        result = await self._retriever.search_hybrid(request)

        # One document must not fill the whole context, so only its best-ranked
        # chunk is eligible; the cap then applies to documents rather than to
        # chunks. The retriever answer itself is returned untouched so the
        # per-stage evidence stays available to the caller.
        selected: list[Candidate] = []
        seen_documents: set[str] = set()
        for candidate in result.results:
            if candidate.document_id in seen_documents:
                continue
            seen_documents.add(candidate.document_id)
            selected.append(candidate)
            if len(selected) == self._citation_limit:
                break
        return OrchestratedRetrieval(result=result, selected=tuple(selected))
