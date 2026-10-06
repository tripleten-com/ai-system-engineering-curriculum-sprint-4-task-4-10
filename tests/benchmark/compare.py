"""Coldline.

===================

File:              tests/benchmark/compare.py
Component:         Benchmark — Evaluation comparison
Purpose:           Compare the two retained reports and apply the published rule.
Interacts With:    tests/benchmark/reports.py, policy.py, metrics.py
Sprint/Task:       Sprint 2 — Project 2 / Task 2.7
Concepts:          Evaluation disagreement, published decision rule
Tools:             Python 3.12, PyYAML

This command measures nothing. It reads the two retained reports, validates
them, and applies the published rule to those figures — the same figures the
assessed checks read. A comparison that re-measured would be comparing
something other than the evidence the recorded answers came from.
"""

from __future__ import annotations

import sys

from tests.benchmark import policy
from tests.benchmark.config import ConfigurationError, changed_parameter
from tests.benchmark.metrics import classify
from tests.benchmark.reports import (
    ReportError,
    RetainedReport,
    impacted_query_ids,
    load_pair,
    measured_configuration,
)


def classification(baseline: RetainedReport, experiment: RetainedReport) -> str:
    """Return the comparison classification for one retained pair of arms."""
    return classify(
        experiment.recall_at_k - baseline.recall_at_k,
        experiment.judge_relevance - baseline.judge_relevance,
    )


def decision(baseline: RetainedReport, experiment: RetainedReport) -> policy.Decision:
    """Return the published rule's decision for one retained pair of arms.

    Raises `policy.PolicyUnpublished` while the rule's constants are
    uncalibrated. Callers must surface that rather than substituting a default.
    """
    return policy.evaluate(
        baseline_recall=baseline.recall_at_k,
        experiment_recall=experiment.recall_at_k,
        baseline_latency_ms=baseline.latency_p95_ms,
        experiment_latency_ms=experiment.latency_p95_ms,
    )


def _print_signals(baseline: RetainedReport, experiment: RetainedReport) -> None:
    """Print the two evaluation signals side by side."""
    print("Authoritative deterministic metric versus comparison-only cached judge evidence.")
    print("They measure different things. The deterministic metric asks how much of the")
    print("labelled relevant material was retrieved; the judge asks how well each retrieved")
    print("passage covers the question. Neither is a correction of the other, and the judge")
    print("takes no part in the adoption rule.")
    print()
    print(f"  {'signal':<28} {'baseline':>10} {'experiment':>12} {'delta':>10}")
    for label, before, after in (
        ("deterministic recall@k", baseline.recall_at_k, experiment.recall_at_k),
        ("cached judge relevance", baseline.judge_relevance, experiment.judge_relevance),
        ("cached judge faithfulness", baseline.judge_faithfulness, experiment.judge_faithfulness),
        ("p50 latency (ms)", baseline.latency_p50_ms, experiment.latency_p50_ms),
        ("p95 latency (ms)", baseline.latency_p95_ms, experiment.latency_p95_ms),
    ):
        print(f"  {label:<28} {before:>10.3f} {after:>12.3f} {after - before:>+10.3f}")
    print()


def _print_decision(baseline: RetainedReport, experiment: RetainedReport) -> int:
    """Print the published rule's decision, or the gate that blocks it."""
    print("Published adoption rule")
    print("  keep = (R1 >= R0) and (L1 <= B) and ((R1 > R0) or ((L0 - L1) > T))")
    try:
        verdict = decision(baseline, experiment)
    except policy.PolicyUnpublished as exc:
        print(f"  BLOCKED: {exc}")
        print()
        print("  No decision can be graded until those constants are published. Nothing here")
        print("  substitutes a default, and in particular `revert` is not the fallback: that")
        print("  would award an answer the evidence has not been tested against.")
        return 1
    except policy.PolicyError as exc:
        print(f"  the published policy is unusable: {exc}", file=sys.stderr)
        return 1
    print(f"  decision: {verdict.decision}")
    print(f"  because:  {verdict.reason}")
    print("  Record it in answers.adoption_decision.")
    return 0


def main() -> int:
    """Compare the retained reports, classify the signals, and apply the rule."""
    try:
        baseline, experiment = load_pair()
    except ReportError as exc:
        print(f"the retained reports are not a valid comparison: {exc}", file=sys.stderr)
        return 1

    try:
        parameter, value = changed_parameter(
            measured_configuration(baseline), measured_configuration(experiment)
        )
        print(f"Tuned parameter: {parameter} = {value:g}")
    except ConfigurationError as exc:
        print(f"Tuned parameter: none ({exc})", file=sys.stderr)
        return 1
    print(f"Retained runs:   baseline {baseline.run_id[:12]}, experiment {experiment.run_id[:12]}")
    print(f"Golden set:      {baseline.fixture_id[:16]} ({len(baseline.query_ids)} queries)")
    print()

    _print_signals(baseline, experiment)

    unjudged = sorted(
        {
            str(chunk)
            for report in (baseline, experiment)
            for row in report.document["queries"]
            for chunk in row["unjudged_chunk_ids"]
        }
    )
    if unjudged:
        print(f"Retrieved chunks with no cached judgement: {', '.join(unjudged)}")
        print("They are excluded from the judge means rather than scored as zero.")
        print()

    print(f"Observed comparison outcome: {classification(baseline, experiment)}")
    print("Record it in answers.agreement_classification.")
    print()

    status = _print_decision(baseline, experiment)
    print()
    impacted = impacted_query_ids(baseline, experiment)
    print(f"Queries the change affected: {', '.join(impacted) or '(none)'}")
    print("Write your regression test against one of them.")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
