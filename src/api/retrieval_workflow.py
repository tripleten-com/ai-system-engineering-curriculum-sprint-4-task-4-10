"""Coldline.

===================

File:              src/api/retrieval_workflow.py
Component:         API — Retrieval workflow
Purpose:           Turn one procedural question into ranked evidence and prompt context.
Interacts With:    The Retriever port, the two internal service contracts, the retrieval route
Sprint/Task:       Sprint 2 — Project 2
Concepts:          Application coordination, extension points, substitutability
Tools:             Python 3.12
"""

from dataclasses import dataclass

from domain.contracts import (
    AssembledContext,
    AuthorizationContext,
    Candidate,
    RetrievalRequest,
    RetrievalResult,
)
from domain.services import ContextAssembler, OrchestratedRetrieval, RetrievalOrchestrator
from ports import Retriever

CITATION_LIMIT = 3


@dataclass(frozen=True)
class RetrievalOutcome:
    """Carry both halves of one answered question."""

    result: RetrievalResult
    context: AssembledContext


class RetrievalWorkflow:
    """Coordinate retrieval and build prompt context.

    Two responsibilities live here: *retrieval orchestration* and *context
    assembly*. Both still have a coupled implementation inline, and both have
    an injection point.

    | Injected | Effect |
    |---|---|
    | nothing | both halves run the inline coupled code |
    | `retrieval_orchestrator` | the injected service replaces the inline orchestration half |
    | `context_assembler` | the injected service replaces the inline assembly half |

    The caller never changes when a service is substituted: the workflow always
    calls the same two methods on whatever satisfies the contract, and the
    composition root decides what that is. The injected services are readable
    so a check can confirm which implementation the running application uses,
    rather than trusting a claim about it.
    """

    def __init__(
        self,
        retriever: Retriever,
        *,
        top_k: int,
        dense_weight: float,
        token_budget: int,
        citation_limit: int = CITATION_LIMIT,
        retrieval_orchestrator: RetrievalOrchestrator | None = None,
        context_assembler: ContextAssembler | None = None,
    ) -> None:
        """Receive the retrieval port, the retrieval parameters, and any extracted services."""
        if citation_limit < 1:
            raise ValueError("citation_limit must be at least 1")
        self._retriever = retriever
        self._top_k = top_k
        self._dense_weight = dense_weight
        self._token_budget = token_budget
        self._citation_limit = citation_limit
        self._retrieval_orchestrator = retrieval_orchestrator
        self._context_assembler = context_assembler

    @property
    def retrieval_orchestrator(self) -> RetrievalOrchestrator | None:
        """Return the injected orchestration service, or None when inline."""
        return self._retrieval_orchestrator

    @property
    def context_assembler(self) -> ContextAssembler | None:
        """Return the injected assembly service, or None when inline."""
        return self._context_assembler

    async def answer(
        self,
        query_id: str,
        text: str,
        authorization: AuthorizationContext,
        *,
        explain: bool = False,
    ) -> RetrievalOutcome:
        """Retrieve evidence for one question and assemble its prompt context."""
        if self._retrieval_orchestrator is not None:
            orchestrated = await self._retrieval_orchestrator.orchestrate(
                query_id, text, authorization, explain=explain
            )
        else:
            orchestrated = await self._orchestrate_inline(
                query_id, text, authorization, explain=explain
            )

        if self._context_assembler is not None:
            context = self._context_assembler.assemble(query_id, orchestrated.selected)
        else:
            context = self._assemble_inline(query_id, orchestrated.selected)
        return RetrievalOutcome(result=orchestrated.result, context=context)

    async def _orchestrate_inline(
        self,
        query_id: str,
        text: str,
        authorization: AuthorizationContext,
        *,
        explain: bool,
    ) -> OrchestratedRetrieval:
        """Run the coupled orchestration half."""
        request = RetrievalRequest(
            query_id=query_id,
            text=text,
            authorization=authorization,
            top_k=self._top_k,
            dense_weight=self._dense_weight,
            explain=explain,
        )
        result = await self._retriever.search_hybrid(request)
        # One document must not fill the whole context, so only its
        # best-ranked chunk is eligible; the cap then applies to documents.
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

    def _assemble_inline(self, query_id: str, selected: tuple[Candidate, ...]) -> AssembledContext:
        """Run the coupled context-assembly half."""
        # The budget is a whole-word count, not a model tokenizer's count. It
        # is a deterministic local stand-in and no claim about a hosted
        # model's context accounting follows from it.
        blocks: list[str] = []
        citations: list[str] = []
        used = 0
        for candidate in selected:
            words = candidate.text.split()
            remaining = self._token_budget - used
            if remaining <= 0:
                break
            trimmed = " ".join(words[:remaining])
            used += len(trimmed.split())
            blocks.append(f"[{candidate.chunk_id}] {trimmed}")
            citations.append(
                f"{candidate.document_id}@{candidate.provenance_revision}"
                f" ({candidate.access.tenant_id}/{candidate.access.access_tier.value})"
            )
        return AssembledContext(
            query_id=query_id,
            prompt_context="\n\n".join(blocks),
            citations=tuple(citations),
            token_budget=self._token_budget,
            used_tokens=used,
        )
