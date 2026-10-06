"""Coldline.

===================

File:              tests/benchmark/reproduce.py
Component:         Benchmark — Reproducibility check
Purpose:           Re-measure both arms and report how far the retained figures drifted.
Interacts With:    tests/benchmark/reports.py and the running experiment endpoint
Sprint/Task:       Sprint 2 — Project 2 / Task 2.7
Concepts:          Reproducibility, measurement variability
Tools:             Python 3.12, httpx

This command re-measures both configurations and prints the difference from the
retained reports. It writes nothing and grades nothing.

That distinction is the whole reason it is a separate command. Recall@K is
deterministic and should reproduce exactly; a difference there means the corpus,
the labels, or the retriever changed. The latency percentiles are wall-clock
measurements from the host, and they will not reproduce exactly — this harness
has produced p95 values from 8.4 ms to 50.6 ms for one unchanged configuration
on one idle machine. Exact equality across runs is not required and is not
checked anywhere.

So a re-measurement can tell you your deterministic evidence is stale. It
cannot replace the inputs an already recorded decision was graded against, and
running it never does.
"""

from __future__ import annotations

import sys

import httpx

from tests.benchmark.config import ConfigurationError, baseline_config, experiment_config
from tests.benchmark.reports import (
    BASELINE_ARM,
    EXPERIMENT_ARM,
    ReportError,
    RetainedReport,
    load_pair,
)
from tests.benchmark.runner import ArmReport, measure_arms
from tests.golden import api_base_url


def _drift(label: str, retained: float, fresh: float, places: int) -> str:
    """Return one drift line."""
    return (
        f"  {label:<28} retained {retained:>10.{places}f}   now {fresh:>10.{places}f}   "
        f"delta {fresh - retained:>+10.{places}f}"
    )


def _compare_arm(retained: RetainedReport, fresh: ArmReport) -> bool:
    """Print one arm's drift and return whether its deterministic metric reproduced."""
    captured = retained.document["captured_at"]
    print(f"{retained.arm} arm (run {retained.run_id[:12]}, captured {captured})")
    print(_drift("deterministic recall@k", retained.recall_at_k, fresh.recall_at_k, 3))
    print(_drift("cached judge relevance", retained.judge_relevance, fresh.judge_relevance, 3))
    print(_drift("p50 latency (ms)", retained.latency_p50_ms, fresh.latency_p50_ms, 1))
    print(_drift("p95 latency (ms)", retained.latency_p95_ms, fresh.latency_p95_ms, 1))
    print()
    return retained.recall_at_k == fresh.recall_at_k


def main() -> int:
    """Re-measure both arms against the retained reports and print the drift."""
    try:
        baseline, experiment = load_pair()
    except ReportError as exc:
        print(f"there is no retained comparison to reproduce: {exc}", file=sys.stderr)
        return 1

    try:
        fresh = measure_arms({BASELINE_ARM: baseline_config(), EXPERIMENT_ARM: experiment_config()})
    except ConfigurationError as exc:
        print(f"retrieval configuration is unusable: {exc}", file=sys.stderr)
        return 1
    except httpx.HTTPError as exc:
        print(f"benchmark could not reach {api_base_url()}: {exc}", file=sys.stderr)
        return 1

    print("Re-measurement against the retained reports. Nothing is rewritten and nothing")
    print("is graded from these figures.")
    print()
    reproduced = [
        _compare_arm(baseline, fresh[BASELINE_ARM]),
        _compare_arm(experiment, fresh[EXPERIMENT_ARM]),
    ]

    if all(reproduced):
        print("Recall@K reproduced exactly on both arms, as a deterministic metric should.")
    else:
        print("Recall@K did not reproduce. It is computed from the published binary labels")
        print("and does not vary between runs, so something the measurement depends on has")
        print("changed: the corpus, the labels, the configuration files, or the retriever.")
        print("Capture both arms again before recording anything from them.")
    print()
    print("The latency percentiles are wall-clock measurements from the host and are not")
    print("expected to reproduce exactly. That is why the published tolerance T is")
    print("calibrated against observed spread rather than assumed to be zero.")
    return 0 if all(reproduced) else 1


if __name__ == "__main__":
    raise SystemExit(main())
