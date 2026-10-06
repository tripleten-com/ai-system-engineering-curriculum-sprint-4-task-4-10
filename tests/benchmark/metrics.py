"""Coldline.

===================

File:              tests/benchmark/metrics.py
Component:         Benchmark — Metrics and comparison
Purpose:           Compute Recall@K, latency percentiles, and the comparison classification.
Interacts With:    tests/golden.py, tests/benchmark/judge.py
Sprint/Task:       Sprint 2 — Project 2 / Task 2.7
Concepts:          Binary relevance, percentiles, evaluation disagreement
Tools:             Python 3.12
"""

from __future__ import annotations

# Both reported metrics are means of values in 0.0 to 1.0, published to three
# decimal places. Half a unit in the last published place is therefore the
# smallest difference the report can express, and a smaller one cannot be
# distinguished from rounding. Every comparison below uses it as the threshold
# of "changed at all". It is a measurement resolution, not a performance target.
METRIC_PLACES = 3
EPSILON = 0.0005

AGREEMENT = "agreement"
DISAGREEMENT = "disagreement"
MIXED_OR_NO_CHANGE = "mixed_or_no_change"
CLASSIFICATIONS = (AGREEMENT, DISAGREEMENT, MIXED_OR_NO_CHANGE)


def recall_at_k(relevant_retrieved: int, total_relevant: int) -> float:
    """Return the proportion of the labelled relevant chunks that were retrieved.

    The labels are binary and structurally derived: every chunk of a query's
    target document is relevant and no other chunk is. No literal word or token
    match is involved.
    """
    if total_relevant < 1:
        raise ValueError("a golden query must have at least one relevant chunk")
    if not 0 <= relevant_retrieved <= total_relevant:
        raise ValueError(
            f"retrieved {relevant_retrieved} relevant chunks of {total_relevant} labelled"
        )
    return relevant_retrieved / total_relevant


def mean(values: list[float]) -> float:
    """Return the arithmetic mean, or 0.0 for no values."""
    return sum(values) / len(values) if values else 0.0


def percentile(samples: list[float], fraction: float) -> float:
    """Return one nearest-rank percentile of the measured samples.

    Nearest-rank on the sorted samples, with no interpolation: the returned
    value is one that was actually measured. For p95 that is the smallest
    sample at or above which 95% of the distribution sits, which is the
    definition this Task's report and checks both use.
    """
    if not samples:
        raise ValueError("no latency samples were collected")
    if not 0.0 < fraction <= 1.0:
        raise ValueError("fraction must be above 0.0 and at most 1.0")
    ordered = sorted(samples)
    rank = max(1, -(-len(ordered) * fraction // 1))
    return ordered[int(rank) - 1]


def direction(delta: float) -> int:
    """Return the sign of one metric delta, treating tiny moves as no move."""
    if delta >= EPSILON:
        return 1
    if delta <= -EPSILON:
        return -1
    return 0


def classify(deterministic_delta: float, judge_delta: float) -> str:
    """Classify how the two evaluation signals moved relative to each other.

    The two signals measure different things: the deterministic metric asks how
    much of the labelled relevant material was retrieved, and the cached judge
    asks how well each retrieved passage covers the question. They are compared
    by direction only. Nothing here infers *why* they moved.

    - ``agreement``: both moved, and in the same direction.
    - ``disagreement``: both moved, in opposite directions.
    - ``mixed_or_no_change``: neither moved, or only one did.
    """
    deterministic = direction(deterministic_delta)
    judge = direction(judge_delta)
    if deterministic == 0 or judge == 0:
        return MIXED_OR_NO_CHANGE
    return AGREEMENT if deterministic == judge else DISAGREEMENT


def rounded(value: float) -> float:
    """Return one quality metric at the published precision."""
    return round(value, METRIC_PLACES)
