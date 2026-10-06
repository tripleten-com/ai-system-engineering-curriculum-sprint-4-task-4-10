"""Coldline.

===================

File:              tests/contract/test_retrieval_contract.py
Component:         Contract tests — Retrieval boundaries
Purpose:           Check retrieval determinism, access-constraint semantics, and SDK isolation.
Interacts With:    Domain retrieval modules, the retrieval adapter, and the corpus fixtures
Sprint/Task:       Sprint 2 — Project 2
Concepts:          Determinism, parameterized predicates, provider isolation
Tools:             Python 3.12, pytest, AST
"""

import ast
import json
from pathlib import Path

import pytest

from adapters.retriever.postgres_hybrid import _constraint_clause
from domain.access import AccessConstraint, UnrestrictedAccessConstraints
from domain.chunking import chunk_document
from domain.contracts import (
    AccessLabel,
    AccessTier,
    AuthorizationContext,
    Candidate,
    DocumentRecord,
    Provenance,
)
from domain.embedding import EMBEDDING_DIMENSIONS, embed, format_vector
from domain.fusion import RANK_CONSTANT, fuse

TASK_ROOT = Path(__file__).resolve().parents[2]
CORPUS = TASK_ROOT / "infra/corpus"
CLOUD_MODULES = {"boto3", "botocore"}


def _document(body: str = "alpha beta gamma delta " * 12) -> DocumentRecord:
    """Return one fixture document with a label and a custody record."""
    return DocumentRecord(
        document_id="sop-fixture-document",
        title="Fixture procedure",
        body=body.strip(),
        access=AccessLabel(tenant_id="tenant-fixture", access_tier=AccessTier.RESTRICTED),
        provenance=Provenance(
            source_uri="s3://coldline-corpus/source/sop-fixture-document.md",
            custodian="Fixture custodian",
            revision="r9",
            recorded_at="2026-03-01T00:00:00+00:00",
        ),
    )


def _candidate(chunk_id: str, rank: int) -> Candidate:
    """Return one ranked candidate fixture."""
    return Candidate(
        chunk_id=chunk_id,
        document_id=chunk_id.split("#", maxsplit=1)[0],
        rank=rank,
        score=1.0 / rank,
        text=f"text for {chunk_id}",
        access=AccessLabel(tenant_id="tenant-fixture", access_tier=AccessTier.STANDARD),
        provenance_revision="r9",
    )


def test_embedding_is_deterministic_and_unit_length() -> None:
    """The same text must embed identically in every process and platform."""
    first = embed("escalation window containment decision")
    second = embed("escalation window containment decision")
    assert first == second
    assert len(first) == EMBEDDING_DIMENSIONS
    assert abs(sum(value * value for value in first) - 1.0) < 1e-9
    assert embed("!!! ---") == tuple([0.0] * EMBEDDING_DIMENSIONS)
    assert format_vector(first).startswith("[") and format_vector(first).endswith("]")


def test_chunking_is_deterministic_and_preserves_label_and_custody() -> None:
    """Chunk identity, tenancy, tier, and custody must survive chunking."""
    document = _document()
    chunks = chunk_document(document)
    assert [chunk.chunk_id for chunk in chunks] == [
        f"{document.document_id}#{index:04d}" for index in range(len(chunks))
    ]
    assert chunk_document(document) == chunks
    assert all(chunk.access == document.access for chunk in chunks)
    assert all(chunk.provenance == document.provenance for chunk in chunks)
    assert " ".join(chunk.text for chunk in chunks) == document.body


def test_fusion_weights_both_arms_and_breaks_ties_deterministically() -> None:
    """Reciprocal-rank fusion must honor the weight and order ties by identity."""
    dense = [_candidate("doc-a#0000", 1), _candidate("doc-b#0000", 2)]
    sparse = [_candidate("doc-b#0000", 1), _candidate("doc-c#0000", 2)]

    balanced = fuse(dense, sparse, dense_weight=0.5, limit=3)
    assert [candidate.chunk_id for candidate in balanced] == [
        "doc-b#0000",
        "doc-a#0000",
        "doc-c#0000",
    ]
    assert balanced[0].score == pytest.approx(0.5 / (RANK_CONSTANT + 2) + 0.5 / (RANK_CONSTANT + 1))

    dense_only = fuse(dense, sparse, dense_weight=1.0, limit=3)
    assert [candidate.chunk_id for candidate in dense_only][:2] == ["doc-a#0000", "doc-b#0000"]
    assert dense_only[-1].score == 0.0

    tied = fuse(
        [_candidate("doc-z#0000", 1)], [_candidate("doc-a#0000", 1)], dense_weight=0.5, limit=2
    )
    assert [candidate.chunk_id for candidate in tied] == ["doc-a#0000", "doc-z#0000"]


def test_fusion_rejects_an_out_of_range_weight_or_limit() -> None:
    """A parameter outside its published range must fail loudly."""
    with pytest.raises(ValueError, match="dense_weight"):
        fuse([], [], dense_weight=1.5, limit=1)
    with pytest.raises(ValueError, match="limit"):
        fuse([], [], dense_weight=0.5, limit=0)


def test_supplied_access_policy_is_explicitly_unrestricted() -> None:
    """The Task 2.1 checkpoint must carry the context without enforcing it."""
    constraint = UnrestrictedAccessConstraints().constrain(
        AuthorizationContext(tenant_id="tenant-northwind", clearance=AccessTier.STANDARD)
    )
    assert constraint == AccessConstraint()
    assert constraint.restricts is False
    assert constraint.denies_everything is False


def test_access_constraint_distinguishes_unrestricted_from_deny_everything() -> None:
    """An empty allowed set must be a visible deny-all, not a silent no-op."""
    assert AccessConstraint(tenant_ids=()).denies_everything is True
    assert AccessConstraint(access_tiers=()).denies_everything is True
    assert AccessConstraint(tenant_ids=("tenant-a",)).denies_everything is False
    assert AccessConstraint(tenant_ids=("tenant-a",)).restricts is True


def test_constraint_clause_is_parameterized_and_encodes_deny_everything() -> None:
    """Constraint translation must emit placeholders only, and never a silent pass."""
    unrestricted, parameters = _constraint_clause(AccessConstraint(), first_placeholder=2)
    assert unrestricted == "true"
    assert parameters == []

    tenant, parameters = _constraint_clause(
        AccessConstraint(tenant_ids=("tenant-a", "tenant-b")), first_placeholder=2
    )
    assert tenant == "tenant_id = ANY($2::text[])"
    assert parameters == [["tenant-a", "tenant-b"]]

    both, parameters = _constraint_clause(
        AccessConstraint(tenant_ids=("tenant-a",), access_tiers=(AccessTier.STANDARD,)),
        first_placeholder=1,
    )
    assert both == "tenant_id = ANY($1::text[]) AND access_tier = ANY($2::text[])"
    assert parameters == [["tenant-a"], ["standard"]]

    deny, parameters = _constraint_clause(AccessConstraint(tenant_ids=()), first_placeholder=2)
    assert deny == "false"
    assert parameters == []


def test_cloud_sdk_imports_stay_inside_the_object_store_adapter() -> None:
    """Application code must reach cloud services only through a published adapter.

    Task 3.3 activates a second cloud-SDK-using adapter alongside object
    storage: LocalStack SQS, behind the ``JobQueue`` port. Task 4.5 adds LocalStack
    Secrets Manager behind the ``SecretProvider`` port.
    """
    offenders: list[str] = []
    for path in (TASK_ROOT / "src").rglob("*.py"):
        relative = path.relative_to(TASK_ROOT).as_posix()
        if relative.startswith(
            ("src/adapters/object_store/", "src/adapters/queue/", "src/adapters/secrets/")
        ):
            continue
        module = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(module):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            if any(name.split(".", maxsplit=1)[0] in CLOUD_MODULES for name in names):
                offenders.append(relative)
    assert sorted(set(offenders)) == []


def test_published_corpus_and_golden_set_agree() -> None:
    """The published fixtures must be internally consistent before anything runs."""
    documents = [
        json.loads(line)
        for line in (CORPUS / "documents.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    provenance = [
        json.loads(line)
        for line in (CORPUS / "provenance.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    queries = [
        json.loads(line)
        for line in (CORPUS / "queries.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    identifiers = {document["document_id"] for document in documents}

    assert len(documents) == len(identifiers) == 18
    assert {entry["document_id"] for entry in provenance} == identifiers
    assert all(entry["synthetic"] is True for entry in provenance)
    assert {query["target_document_id"] for query in queries} <= identifiers
    assert len({query["query_id"] for query in queries}) == len(queries) == 11
    assert {document["access"]["access_tier"] for document in documents} == {
        "standard",
        "restricted",
    }
    assert len({document["access"]["tenant_id"] for document in documents}) == 3
