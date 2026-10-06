"""Coldline.

===================

File:              tests/unit/domain/test_retrieval_domain.py
Component:         Unit tests — Retrieval domain
Purpose:           Check retrieval contracts, chunk identity, and context assembly in isolation.
Interacts With:    Domain contracts, chunking, and the coupled retrieval workflow
Sprint/Task:       Sprint 2 — Project 2
Concepts:          Immutable contracts, deterministic behavior, coupling
Tools:             Python 3.12, pytest
"""

import pytest
from pydantic import ValidationError

from api.retrieval_workflow import RetrievalWorkflow
from domain.contracts import (
    AccessLabel,
    AccessTier,
    AssembledContext,
    AuthorizationContext,
    Candidate,
    ChunkRecord,
    Provenance,
    RetrievalRequest,
    RetrievalResult,
    RetrievalStage,
    StageEvidence,
)
from domain.embedding import embed

LABEL = AccessLabel(tenant_id="tenant-fixture", access_tier=AccessTier.STANDARD)
PROVENANCE = Provenance(
    source_uri="s3://coldline-corpus/source/sop-fixture.md",
    custodian="Fixture custodian",
    revision="r1",
    recorded_at="2026-03-01T00:00:00+00:00",
)


def _candidate(chunk_id: str, rank: int, text: str) -> Candidate:
    """Return one ranked candidate fixture."""
    return Candidate(
        chunk_id=chunk_id,
        document_id=chunk_id.split("#", maxsplit=1)[0],
        rank=rank,
        score=1.0 / rank,
        text=text,
        access=LABEL,
        provenance_revision="r1",
    )


class _StubRetriever:
    """Return a fixed ranking without touching a database."""

    def __init__(self, candidates: list[Candidate]) -> None:
        """Record the candidates this stub returns and the requests it saw."""
        self._candidates = candidates
        self.requests: list[RetrievalRequest] = []

    async def search_hybrid(self, request: RetrievalRequest) -> RetrievalResult:
        """Return the fixed ranking and echo the request parameters back."""
        self.requests.append(request)
        limited = self._candidates[: request.top_k]
        return RetrievalResult(
            query_id=request.query_id,
            results=tuple(limited),
            stages=(
                StageEvidence(
                    stage=RetrievalStage.FUSION,
                    admitted=tuple(candidate.chunk_id for candidate in limited),
                ),
            ),
            authorization_enforced=False,
        )


def test_chunk_identity_must_match_its_document_and_position() -> None:
    """A chunk identifier that is not derived from its position is rejected."""
    with pytest.raises(ValidationError, match="chunk_id must be"):
        ChunkRecord(
            chunk_id="sop-fixture#7",
            document_id="sop-fixture",
            chunk_index=7,
            text="fixture text",
            embedding=embed("fixture text"),
            access=LABEL,
            provenance=PROVENANCE,
        )


def test_chunk_requires_a_non_empty_embedding() -> None:
    """A chunk with no embedding cannot participate in the dense arm."""
    with pytest.raises(ValidationError, match="embedding must not be empty"):
        ChunkRecord(
            chunk_id="sop-fixture#0000",
            document_id="sop-fixture",
            chunk_index=0,
            text="fixture text",
            embedding=(),
            access=LABEL,
            provenance=PROVENANCE,
        )


def test_retrieval_result_reports_a_missing_stage_loudly() -> None:
    """Asking for evidence a run never produced must fail rather than return empty."""
    result = RetrievalResult(
        query_id="q-fixture", results=(), stages=(), authorization_enforced=False
    )
    with pytest.raises(KeyError, match="dense"):
        result.stage(RetrievalStage.DENSE)


def test_assembled_context_cannot_exceed_its_budget() -> None:
    """A context claiming to use more than its budget is invalid by construction."""
    with pytest.raises(ValidationError, match="used_tokens"):
        AssembledContext(
            query_id="q-fixture",
            prompt_context="text",
            citations=(),
            token_budget=10,
            used_tokens=11,
        )


def test_authorization_context_rejects_a_malformed_tenant() -> None:
    """Tenancy identifiers follow one lowercase shape everywhere."""
    with pytest.raises(ValidationError):
        AuthorizationContext(tenant_id="Tenant Northwind", clearance=AccessTier.STANDARD)


async def test_workflow_passes_the_supplied_parameters_and_caller_context() -> None:
    """The coupled workflow must build the request from its configured parameters."""
    retriever = _StubRetriever([_candidate("sop-a#0000", 1, "alpha beta gamma")])
    workflow = RetrievalWorkflow(retriever, top_k=4, dense_weight=0.25, token_budget=64)
    authorization = AuthorizationContext(tenant_id="tenant-fixture", clearance=AccessTier.STANDARD)

    await workflow.answer("q-fixture", "alpha beta", authorization)

    request = retriever.requests[0]
    assert (request.top_k, request.dense_weight, request.explain) == (4, 0.25, False)
    assert request.authorization == authorization


async def test_workflow_keeps_one_chunk_per_document_and_caps_citations() -> None:
    """Selection must not let one document fill the whole prompt context."""
    retriever = _StubRetriever(
        [
            _candidate("sop-a#0000", 1, "first chunk of a"),
            _candidate("sop-a#0001", 2, "second chunk of a"),
            _candidate("sop-b#0000", 3, "first chunk of b"),
            _candidate("sop-c#0000", 4, "first chunk of c"),
            _candidate("sop-d#0000", 5, "first chunk of d"),
        ]
    )
    workflow = RetrievalWorkflow(retriever, top_k=5, dense_weight=0.5, token_budget=64)

    outcome = await workflow.answer(
        "q-fixture",
        "alpha",
        AuthorizationContext(tenant_id="tenant-fixture", clearance=AccessTier.STANDARD),
    )

    assert outcome.context.citations == (
        "sop-a@r1 (tenant-fixture/standard)",
        "sop-b@r1 (tenant-fixture/standard)",
        "sop-c@r1 (tenant-fixture/standard)",
    )
    assert "sop-a#0001" not in outcome.context.prompt_context


async def test_workflow_trims_context_to_the_token_budget() -> None:
    """The assembled context must respect its declared budget exactly."""
    retriever = _StubRetriever([_candidate("sop-a#0000", 1, "one two three four five six")])
    workflow = RetrievalWorkflow(retriever, top_k=1, dense_weight=0.5, token_budget=3)

    outcome = await workflow.answer(
        "q-fixture",
        "alpha",
        AuthorizationContext(tenant_id="tenant-fixture", clearance=AccessTier.STANDARD),
    )

    assert outcome.context.used_tokens == 3
    assert outcome.context.prompt_context == "[sop-a#0000] one two three"
