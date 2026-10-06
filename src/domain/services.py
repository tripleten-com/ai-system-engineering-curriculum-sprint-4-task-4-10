"""Coldline.

===================

File:              src/domain/services.py
Component:         Domain — Internal service contracts
Purpose:           Define the two supported internal service boundaries and their contracts.
Interacts With:    The retrieval workflow, student extensions, and supplied test doubles
Sprint/Task:       Sprint 2 — Project 2
Concepts:          Responsibility boundaries, dependency inversion, substitutability
Tools:             Python 3.12, Pydantic
"""

from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict

from domain.contracts import (
    AssembledContext,
    AuthorizationContext,
    Candidate,
    RetrievalResult,
)


class OrchestratedRetrieval(BaseModel):
    """Carry what retrieval orchestration produces for one question.

    ``result`` is the whole retriever answer, including per-stage evidence, and
    ``selected`` is the subset orchestration chose to hand downstream.
    Returning both keeps the evidence available to callers while making the
    selection decision an explicit output rather than a hidden side effect.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    result: RetrievalResult
    selected: tuple[Candidate, ...]


@runtime_checkable
class RetrievalOrchestrator(Protocol):
    """Coordinate one retrieval request and choose the candidates to carry forward.

    This is one of the two supported Task 2.2 extractions. An implementation
    owns:

    1. resolving the controlled parameters (`top_k`, `dense_weight`),
    2. building the request from the caller's identity and question,
    3. invoking the `Retriever` port,
    4. selecting the candidates that go downstream — at most one chunk per
       document, capped at the citation limit, in fused rank order.

    An implementation must depend on the `Retriever` *port*, never on a
    concrete adapter, a database driver, or a cloud SDK, and it must never
    import the caller that uses it.
    """

    async def orchestrate(
        self,
        query_id: str,
        text: str,
        authorization: AuthorizationContext,
        *,
        explain: bool = False,
    ) -> OrchestratedRetrieval:
        """Return the retriever answer and the candidates selected from it.

        Behavior contract:

        - *request construction*: the request carries ``query_id``, ``text``,
          the caller's ``authorization``, the configured ``top_k`` and
          ``dense_weight``, and the ``explain`` flag unchanged.
        - *selection*: at most one candidate per ``document_id``, keeping the
          best-ranked chunk of each.
        - *cap*: at most ``citation_limit`` candidates.
        - *order*: ``selected`` keeps the fused rank order of
          ``result.results``.
        - *evidence*: ``result`` is returned unmodified.
        """
        ...


@runtime_checkable
class ContextAssembler(Protocol):
    """Turn selected candidates into prompt context and citations.

    This is the other supported Task 2.2 extraction. An implementation owns
    token budgeting, prompt formatting, and citation construction, and nothing
    else. It performs no retrieval and touches no infrastructure.
    """

    def assemble(self, query_id: str, selected: tuple[Candidate, ...]) -> AssembledContext:
        """Return the prompt context and citations for one selected candidate set.

        Behavior contract:

        - *budget*: ``used_tokens`` never exceeds the configured
          ``token_budget``, where one token is one whitespace-separated word.
        - *trimming*: a candidate whose text does not fit is trimmed to the
          remaining budget rather than dropped silently.
        - *block format*: each block is ``[<chunk_id>] <text>``, and blocks are
          joined by one blank line.
        - *citations*: one citation per included candidate, formatted
          ``<document_id>@<provenance_revision> (<tenant_id>/<access_tier>)``,
          in the same order.
        - *exhausted budget*: once the budget is spent, the remaining
          candidates are omitted.
        """
        ...
