"""Coldline.

===================

File:              tests/unit/benchmark/test_experiment_harness.py
Component:         Unit tests — Experiment harness
Purpose:           Check configuration validation, metrics, classification, and the policy.
Interacts With:    tests/benchmark
Sprint/Task:       Sprint 2 — Project 2 / Task 2.7
Concepts:          Deterministic evaluation, percentiles, evidence-supported decisions
Tools:             Python 3.12, pytest
"""

import inspect
import json
from pathlib import Path

import pytest

from domain.chunking import chunk_document
from domain.contracts import AccessLabel, AccessTier, DocumentRecord, Provenance
from tests.benchmark import policy
from tests.benchmark.config import (
    CANDIDATE_POOL,
    ConfigurationError,
    RetrievalConfig,
    baseline_config,
    changed_parameter,
    load_config,
)
from tests.benchmark.judge import load_judge
from tests.benchmark.metrics import (
    AGREEMENT,
    DISAGREEMENT,
    EPSILON,
    MIXED_OR_NO_CHANGE,
    classify,
    percentile,
    recall_at_k,
)
from tests.benchmark.runner import chunk_counts
from tests.golden import load_queries

TASK_ROOT = Path(__file__).resolve().parents[3]
BASELINE = RetrievalConfig(top_k=3, fusion_weight=0.5)


def write(path: Path, body: str) -> Path:
    """Write one configuration file for a validation check."""
    path.write_text(body, encoding="utf-8")
    return path


def test_the_committed_baseline_is_the_documented_control() -> None:
    """The control arm must be the configuration the earlier Tasks documented."""
    assert baseline_config() == BASELINE


def test_the_experiment_configuration_is_usable() -> None:
    """Whatever a student sets, the experimental configuration must stay valid.

    This says nothing about the value: tuning it is the Task. It says the file
    still parses and still names both approved parameters within their bounds,
    so the harness measures a configuration the retriever can honor.
    """
    assert load_config(TASK_ROOT / "config/student/retrieval.yaml")


@pytest.mark.parametrize(
    "body,message",
    [
        ("retrieval: {top_k: 3}\n", "missing parameters"),
        ("retrieval: {top_k: 3, fusion_weight: 0.5, extra: 1}\n", "unapproved parameters"),
        ("retrieval: {top_k: 0, fusion_weight: 0.5}\n", "top_k must be between"),
        (f"retrieval: {{top_k: {CANDIDATE_POOL + 1}, fusion_weight: 0.5}}\n", "top_k must be"),
        ("retrieval: {top_k: 2.5, fusion_weight: 0.5}\n", "whole number"),
        ("retrieval: {top_k: true, fusion_weight: 0.5}\n", "whole number"),
        ("retrieval: {top_k: 3, fusion_weight: 1.5}\n", "fusion_weight must be between"),
        ("retrieval: {top_k: 3, fusion_weight: high}\n", "fusion_weight must be a number"),
        ("top_k: 3\n", "top-level `retrieval` mapping"),
        ("retrieval: 3\n", "must be a mapping"),
    ],
    ids=[
        "missing-parameter",
        "extra-parameter",
        "top-k-too-small",
        "top-k-above-pool",
        "top-k-fractional",
        "top-k-boolean",
        "fusion-weight-too-large",
        "fusion-weight-not-numeric",
        "no-retrieval-mapping",
        "retrieval-not-a-mapping",
    ],
)
def test_unusable_configurations_are_rejected(tmp_path: Path, body: str, message: str) -> None:
    """A configuration the retriever cannot honor must fail loudly, not silently."""
    with pytest.raises(ConfigurationError, match=message):
        load_config(write(tmp_path / "retrieval.yaml", body))


def test_no_change_is_not_an_experiment() -> None:
    """An untuned configuration must be reported, not measured as a null result."""
    with pytest.raises(ConfigurationError, match="still identical to the baseline"):
        changed_parameter(BASELINE, BASELINE)


def test_two_changes_are_not_a_controlled_experiment() -> None:
    """With two variables moving, no measured shift can be attributed to either."""
    with pytest.raises(ConfigurationError, match="exactly one approved parameter"):
        changed_parameter(BASELINE, RetrievalConfig(top_k=5, fusion_weight=0.2))


@pytest.mark.parametrize(
    "experiment,expected",
    [
        (RetrievalConfig(top_k=5, fusion_weight=0.5), ("top_k", 5.0)),
        (RetrievalConfig(top_k=3, fusion_weight=0.2), ("fusion_weight", 0.2)),
    ],
    ids=["top-k", "fusion-weight"],
)
def test_the_single_changed_parameter_is_identified(
    experiment: RetrievalConfig, expected: tuple[str, float]
) -> None:
    """Both approved parameters must be recognized when tuned alone."""
    assert changed_parameter(BASELINE, experiment) == expected


def test_recall_is_the_labelled_proportion_retrieved() -> None:
    """Recall@K counts labelled relevant chunks, not word matches."""
    assert recall_at_k(0, 3) == 0.0
    assert recall_at_k(1, 3) == pytest.approx(1 / 3)
    assert recall_at_k(3, 3) == 1.0


@pytest.mark.parametrize(
    "relevant,total",
    [(-1, 3), (4, 3), (0, 0)],
    ids=["negative", "above-total", "no-labels"],
)
def test_impossible_recall_inputs_are_rejected(relevant: int, total: int) -> None:
    """A denominator of zero or an impossible numerator is a harness defect."""
    with pytest.raises(ValueError):
        recall_at_k(relevant, total)


def test_percentile_is_nearest_rank_over_measured_samples() -> None:
    """The reported percentile must be a value that was actually measured."""
    samples = [float(value) for value in range(1, 101)]
    assert percentile(samples, 0.50) == 50.0
    assert percentile(samples, 0.95) == 95.0
    assert percentile(samples, 1.0) == 100.0
    assert percentile([4.0], 0.95) == 4.0


def test_percentile_rejects_an_empty_measurement() -> None:
    """No samples means no measurement, not a percentile of zero."""
    with pytest.raises(ValueError, match="no latency samples"):
        percentile([], 0.95)


@pytest.mark.parametrize(
    "deterministic,judge,expected",
    [
        (0.05, 0.05, AGREEMENT),
        (-0.05, -0.05, AGREEMENT),
        (0.05, -0.05, DISAGREEMENT),
        (-0.05, 0.05, DISAGREEMENT),
        (0.0, 0.0, MIXED_OR_NO_CHANGE),
        (0.05, 0.0, MIXED_OR_NO_CHANGE),
        (0.0, 0.05, MIXED_OR_NO_CHANGE),
        (EPSILON / 2, EPSILON / 2, MIXED_OR_NO_CHANGE),
    ],
    ids=[
        "both-up",
        "both-down",
        "quality-up-judge-down",
        "quality-down-judge-up",
        "neither-moved",
        "only-deterministic-moved",
        "only-judge-moved",
        "below-measurement-resolution",
    ],
)
def test_classification_compares_direction_only(
    deterministic: float, judge: float, expected: str
) -> None:
    """The two signals are compared by direction, and tiny moves are not moves."""
    assert classify(deterministic, judge) == expected


def test_the_adoption_rule_ignores_the_comparison_only_judge() -> None:
    """A heuristic stand-in must not decide an adoption question.

    ``policy.decide`` takes no judge argument at all, which is the guarantee:
    there is no way to give the cached judge a vote in the published rule. Its
    boundary behavior is qualified separately in
    ``tests/unit/benchmark/test_adoption_rule.py``.
    """
    parameters = inspect.signature(policy.decide).parameters
    assert not [name for name in parameters if "judge" in name]


def test_chunk_counts_match_the_runtime_chunking_rule() -> None:
    """The Recall@K denominator must be the chunking the runtime actually performs."""
    counts = chunk_counts()
    for line in (
        (TASK_ROOT / "infra/corpus/documents.jsonl").read_text(encoding="utf-8").splitlines()
    ):
        if not line.strip():
            continue
        record = json.loads(line)
        access = record["access"]
        provenance = record["provenance"]
        document = DocumentRecord(
            document_id=record["document_id"],
            title=record["title"],
            body=record["body"],
            access=AccessLabel(
                tenant_id=access["tenant_id"], access_tier=AccessTier(access["access_tier"])
            ),
            provenance=Provenance(
                source_uri=provenance["source_uri"],
                custodian=provenance["custodian"],
                revision=provenance["revision"],
                recorded_at=provenance["recorded_at"],
            ),
        )
        assert counts[document.document_id] == len(chunk_document(document))


def test_every_published_query_has_cached_judge_evidence() -> None:
    """A query with no cached judgement could not take part in the comparison."""
    judge = load_judge()
    assert judge.judge_identities == ["coldline-cached-heuristic-v1"]
    for query in load_queries():
        judged = judge.judged_chunks(query.query_id)
        assert judged, f"{query.query_id} has no cached judge evidence"
        assert any(chunk.startswith(f"{query.target_document_id}#") for chunk in judged), (
            f"{query.query_id} has no judged chunk from its own target document"
        )
