"""Coldline.

===================

File:              tests/benchmark/run.py
Component:         Benchmark — Arm capture
Purpose:           Measure one retrieval configuration and retain its report.
Interacts With:    tests/benchmark/runner.py, reports.py, the running experiment endpoint
Sprint/Task:       Sprint 2 — Project 2 / Task 2.7
Concepts:          Controlled experiment, write-once run artifacts
Tools:             Python 3.12, httpx

One command, one arm, one retained report. `poe benchmark-baseline` measures
the supplied baseline; `poe benchmark-experiment` measures whatever
`config/student/retrieval.yaml` says. Neither can write the other's report.

Capturing the arms separately is what makes the baseline report survive an
experiment run, and the recorded decision gradeable against the evidence it
was actually read from. It also means the two arms are measured minutes apart
rather than interleaved, so their p95 figures carry the host's own drift
between the captures. That is a real cost, and it is why the published latency
tolerance `T` has to be calibrated against the spread repeated runs show on
the supported environment profiles rather than guessed; see
`config/adoption-policy.yaml`.
"""

from __future__ import annotations

import argparse
import sys

import httpx

from tests.benchmark.config import (
    ConfigurationError,
    RetrievalConfig,
    baseline_config,
    experiment_config,
)
from tests.benchmark.reports import (
    ARMS,
    BASELINE_ARM,
    ReportError,
    report_path,
    retain,
)
from tests.benchmark.runner import ArmReport, measure_arms
from tests.golden import api_base_url


def measure(arm: str, config: RetrievalConfig) -> ArmReport:
    """Measure one configuration against the whole golden evaluation set."""
    return measure_arms({arm: config})[arm]


def _summary(report: ArmReport) -> str:
    """Return one report line for one arm."""
    return (
        f"{report.arm:<11} top_k={report.config['top_k']:<4g} "
        f"fusion_weight={report.config['fusion_weight']:<5g} "
        f"recall@k={report.recall_at_k:<6.3f} "
        f"judge={report.judge_relevance:<6.3f} "
        f"p50={report.latency_p50_ms:>7.1f}ms p95={report.latency_p95_ms:>7.1f}ms "
        f"p99={report.latency_p99_ms:>7.1f}ms"
    )


def _arguments(argv: list[str] | None) -> argparse.Namespace:
    """Parse the capture arguments."""
    parser = argparse.ArgumentParser(
        description="Measure one retrieval configuration and retain its report."
    )
    parser.add_argument("--arm", choices=ARMS, required=True, help="which arm to capture")
    parser.add_argument(
        "--recapture",
        action="store_true",
        help=(
            "discard an existing report for this arm and measure again; recapturing the "
            "baseline also discards the experiment report, because a baseline and an "
            "experiment measured at different times are not a comparison"
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Measure the named arm, retain its report, and print what to record."""
    arguments = _arguments(argv)
    arm = arguments.arm

    try:
        config = baseline_config() if arm == BASELINE_ARM else experiment_config()
    except ConfigurationError as exc:
        print(f"retrieval configuration is unusable: {exc}", file=sys.stderr)
        return 1

    try:
        report = measure(arm, config)
    except httpx.HTTPError as exc:
        print(f"benchmark could not reach {api_base_url()}: {exc}", file=sys.stderr)
        print(
            "Start the stack with `poe start` and ingest with `poe ingest` first.", file=sys.stderr
        )
        return 1

    try:
        path = retain(report, recapture=arguments.recapture)
    except ReportError as exc:
        print(f"report not retained: {exc}", file=sys.stderr)
        return 1

    print(f"Golden evaluation set: {len(report.query_ids)} queries")
    print(f"Golden set digest:     {report.golden_set_digest}")
    print(f"Latency samples:       {report.latency_samples}")
    print()
    print(_summary(report))
    print()
    print("Per-query deterministic recall and cached judge relevance:")
    print(f"  {'query_id':<22} {'recall':>7}  {'judge relevance':>16}")
    for outcome in report.queries:
        print(f"  {outcome.query_id:<22} {outcome.recall:>7.3f}  {outcome.judge_relevance:>16.3f}")
    print()
    print(f"Retained {arm} report: {path.parent.name}/{path.name}")
    if report.failed_query_ids:
        print(f"Failed queries: {', '.join(report.failed_query_ids)}", file=sys.stderr)
        print(
            "A report with a failed query is rejected by the report contract. Fix the failure "
            "and capture this arm again.",
            file=sys.stderr,
        )
        return 1

    if arm == BASELINE_ARM:
        print()
        print("Record answers.baseline_recall_at_k from the recall@k column and")
        print("answers.baseline_latency_ms from the p95 column - not p50, not p99.")
        print("Then change one approved parameter in config/student/retrieval.yaml and run")
        print("`poe benchmark-experiment`.")
        return 0

    if not report_path(BASELINE_ARM).is_file():
        print()
        print(
            "There is no retained baseline report to compare this against. Run "
            "`poe benchmark-baseline` first.",
            file=sys.stderr,
        )
        return 1
    print()
    print("Record answers.experiment_recall_at_k and answers.experiment_latency_ms the same")
    print("way, then run `poe compare` for the judge comparison and the published rule.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
