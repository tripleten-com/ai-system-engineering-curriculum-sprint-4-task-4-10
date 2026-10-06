"""Coldline.

===================

File:              tests/contract/test_benchmark_reports.py
Component:         Contract tests — Retained benchmark reports
Purpose:           Verify that an invalid or missing report fails validation.
Interacts With:    tests/benchmark/reports.py and docs/contracts/benchmark-report.schema.json
Sprint/Task:       Sprint 2 — Project 2 / Task 2.7
Concepts:          Report provenance, fail-closed validation, retention
Tools:             Python 3.12, pytest

Assesses nothing. It checks the mechanism the assessed checks depend on: that a
missing, malformed, stale, mismatched, or self-inconsistent retained report is
*rejected*, and specifically that it is not quietly turned into a decision.

Every case here builds a report document in a temporary directory and points
the loader at it, so nothing touches a real capture.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from tests.benchmark import reports
from tests.benchmark.config import baseline_config

TASK_ROOT = Path(__file__).parents[2]

# `runtime` is not needed: none of this reaches the stack. The report documents
# are written here, so the checks run in the same profile as the other
# no-container contract tests.


def _query_row(query_id: str, recall: float) -> dict[str, Any]:
    """Return one internally consistent per-query row."""
    relevant = round(recall * 4)
    return {
        "query_id": query_id,
        "retrieved_chunk_ids": [f"{query_id}-chunk-{index}" for index in range(3)],
        "relevant_retrieved": relevant,
        "total_relevant": 4,
        "recall": relevant / 4,
        "judge_relevance": 0.5,
        "judge_faithfulness": 0.5,
        "unjudged_chunk_ids": [],
    }


def _document(arm: str, **overrides: Any) -> dict[str, Any]:
    """Return one valid report document for the named arm."""
    rows = [_query_row("q-one", 1.0), _query_row("q-two", 0.5)]
    config = (
        baseline_config().as_mapping()
        if arm == reports.BASELINE_ARM
        else {"top_k": 3, "fusion_weight": 0.5}
    )
    digest = reports.golden_set_digest()
    template_id, harness_version = reports.template_identity()
    document: dict[str, Any] = {
        "report_schema_version": reports.REPORT_SCHEMA_VERSION,
        "harness_version": harness_version,
        "template_id": template_id,
        "fixture_id": digest,
        "golden_set_digest": digest,
        "configuration_id": reports.configuration_id(config),
        "run_id": "0" * 31 + ("1" if arm == reports.BASELINE_ARM else "2"),
        "captured_at": "2026-09-07T10:00:00Z",
        "arm": arm,
        "config": config,
        "query_ids": [str(row["query_id"]) for row in rows],
        "failed_query_ids": [],
        "recall_at_k": 0.75,
        "judge_relevance": 0.5,
        "judge_faithfulness": 0.5,
        "latency_p50_ms": 12.0,
        "latency_p95_ms": 20.0,
        "latency_p99_ms": 24.0,
        "latency_samples": 30,
        "queries": rows,
    }
    document.update(overrides)
    return document


@pytest.fixture
def retained(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Callable[..., Path]:
    """Return a helper that writes report documents into an isolated directory."""
    monkeypatch.setenv(reports.REPORT_DIRECTORY_OVERRIDE, str(tmp_path))

    def write(arm: str, **overrides: Any) -> Path:
        path = tmp_path / f"{arm}.json"
        path.write_text(json.dumps(_document(arm, **overrides), indent=2), encoding="utf-8")
        return path

    return write


def test_a_missing_report_fails_validation(retained: Callable[..., Path]) -> None:
    """There is nothing to grade against, and that is an error rather than a default."""
    retained(reports.BASELINE_ARM)

    with pytest.raises(reports.ReportError, match="experiment.json is missing"):
        reports.load_pair()


def test_a_malformed_report_fails_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file that is not readable JSON is rejected by name."""
    monkeypatch.setenv(reports.REPORT_DIRECTORY_OVERRIDE, str(tmp_path))
    (tmp_path / "baseline.json").write_text("{not json", encoding="utf-8")

    with pytest.raises(reports.ReportError, match="not readable JSON"):
        reports.load(reports.BASELINE_ARM)


def test_a_report_missing_its_provenance_is_rejected(retained: Callable[..., Path]) -> None:
    """The contract requires the identifiers, so a report without them is not gradeable."""
    path = retained(reports.BASELINE_ARM)
    document = json.loads(path.read_text(encoding="utf-8"))
    del document["run_id"]
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(reports.ReportError, match="report contract"):
        reports.load(reports.BASELINE_ARM)


def test_a_report_from_another_template_is_rejected(retained: Callable[..., Path]) -> None:
    """A report captured elsewhere is not evidence about this template."""
    retained(reports.BASELINE_ARM, template_id="coldline-task-2-6")

    with pytest.raises(reports.ReportError, match="report contract"):
        reports.load(reports.BASELINE_ARM)


def test_a_report_from_another_harness_version_is_rejected(
    retained: Callable[..., Path],
) -> None:
    """A different measurement procedure makes the figures incomparable."""
    retained(reports.BASELINE_ARM, harness_version=99)

    with pytest.raises(reports.ReportError, match="report contract"):
        reports.load(reports.BASELINE_ARM)


def test_a_report_with_a_failed_query_is_rejected(retained: Callable[..., Path]) -> None:
    """A measurement that did not complete is not a basis for a decision."""
    retained(reports.BASELINE_ARM, failed_query_ids=["q-two"])

    with pytest.raises(reports.ReportError, match="failed queries"):
        reports.load(reports.BASELINE_ARM)


def test_a_report_whose_totals_disagree_with_its_rows_is_rejected(
    retained: Callable[..., Path],
) -> None:
    """An aggregate edited away from the rows it summarizes is self-inconsistent."""
    retained(reports.BASELINE_ARM, recall_at_k=0.999)

    with pytest.raises(reports.ReportError, match="recall_at_k"):
        reports.load(reports.BASELINE_ARM)


def test_a_report_claiming_a_configuration_it_did_not_measure_is_rejected(
    retained: Callable[..., Path],
) -> None:
    """The configuration identifier is recomputed, so it cannot be asserted."""
    retained(reports.BASELINE_ARM, configuration_id="0" * 64)

    with pytest.raises(reports.ReportError, match="configuration identifier"):
        reports.load(reports.BASELINE_ARM)


def test_reports_with_unordered_percentiles_are_rejected(
    retained: Callable[..., Path],
) -> None:
    """A p95 below the p50 is not a percentile pair from one distribution."""
    retained(reports.BASELINE_ARM, latency_p50_ms=30.0, latency_p95_ms=20.0)

    with pytest.raises(reports.ReportError, match="not ordered"):
        reports.load(reports.BASELINE_ARM)


def test_reports_measured_against_different_fixtures_are_not_a_comparison(
    retained: Callable[..., Path],
) -> None:
    """Two arms have to have run against the identical golden set."""
    retained(reports.BASELINE_ARM)
    other = "f" * 64
    retained(reports.EXPERIMENT_ARM, fixture_id=other, golden_set_digest=other)

    with pytest.raises(reports.ReportError, match="different golden evaluation sets"):
        reports.load_pair()


def test_reports_from_one_capture_are_not_two_runs(retained: Callable[..., Path]) -> None:
    """A single capture presented as both arms is rejected."""
    shared = "a" * 32
    retained(reports.BASELINE_ARM, run_id=shared)
    retained(reports.EXPERIMENT_ARM, run_id=shared)

    with pytest.raises(reports.ReportError, match="same run identifier"):
        reports.load_pair()


def test_two_identical_configurations_are_not_an_experiment(
    retained: Callable[..., Path],
) -> None:
    """Measuring the baseline twice is not a controlled experiment."""
    supplied = baseline_config().as_mapping()
    retained(reports.BASELINE_ARM)
    retained(
        reports.EXPERIMENT_ARM,
        config=supplied,
        configuration_id=reports.configuration_id(supplied),
    )

    with pytest.raises(reports.ReportError, match="no experiment was run"):
        reports.load_pair()


def test_a_baseline_report_measuring_another_configuration_is_rejected(
    retained: Callable[..., Path],
) -> None:
    """The control arm must be the supplied control."""
    tampered = {"top_k": 2, "fusion_weight": 0.25}
    retained(
        reports.BASELINE_ARM,
        config=tampered,
        configuration_id=reports.configuration_id(tampered),
    )
    retained(reports.EXPERIMENT_ARM)

    with pytest.raises(reports.ReportError, match="must measure the supplied"):
        reports.load_pair()


def test_the_two_arms_have_separate_retained_paths() -> None:
    """An experiment capture must not be able to write the baseline evidence."""
    assert reports.report_path(reports.BASELINE_ARM) != reports.report_path(reports.EXPERIMENT_ARM)


def test_an_unknown_arm_has_no_retained_path() -> None:
    """Only the two published arms are retained."""
    with pytest.raises(reports.ReportError, match="arm must be one of"):
        reports.report_path("control")


def test_the_published_report_paths_are_the_documented_ones() -> None:
    """The contract publishes these exact paths, so they are asserted."""
    assert reports.REPORT_DIRECTORY == TASK_ROOT / ".benchmark"
    assert reports.REPORT_DIRECTORY.name + "/baseline.json" == ".benchmark/baseline.json"


def test_an_invalid_comparison_never_yields_a_decision(retained: Callable[..., Path]) -> None:
    """The fail-closed guarantee, asserted rather than assumed.

    A comparison that cannot be validated must raise. If it returned a decision
    instead, an unmeasured submission would be graded against whichever answer
    the fallback happened to be.
    """
    retained(reports.BASELINE_ARM)

    with pytest.raises(reports.ReportError):
        reports.load_pair()


def test_the_report_contract_is_the_published_one() -> None:
    """The loader validates against the contract shipped in docs/contracts."""
    assert reports.REPORT_CONTRACT == TASK_ROOT / "docs/contracts/benchmark-report.schema.json"
    schema = json.loads(reports.REPORT_CONTRACT.read_text(encoding="utf-8"))
    assert schema["properties"]["template_id"]["const"] == "coldline-task-2-7"
