"""Coldline.

===================

File:              tests/benchmark/policy.py
Component:         Benchmark — Published adoption decision rule
Purpose:           Apply the one published keep-or-revert rule to a valid comparison.
Interacts With:    config/adoption-policy.yaml, tests/benchmark/reports.py
Sprint/Task:       Sprint 2 — Project 2 / Task 2.7
Concepts:          Published decision rule, calibrated constants, fail-closed gating
Tools:             Python 3.12, PyYAML

There is exactly one decision rule, it is published in
`config/adoption-policy.yaml`, and it is not a matter of judgment:

    keep = (R1 >= R0) and (L1 <= B) and ((R1 > R0) or ((L0 - L1) > T))

with `revert` for every other valid comparison. `R0`/`R1` are the two arms'
Recall@K at the same evaluation cutoff and `L0`/`L1` their p95 latencies in
milliseconds; `B` is the published latency budget and `T` the published
positive latency tolerance.

Three things about the rule are worth reading twice. Equality with the budget
is allowed, so an experiment that lands exactly on `B` has met it. Equality
with the tolerance is not enough, so a latency improvement has to *exceed* `T`
to carry a keep decision on its own. And a recall loss is never accepted, no
matter how much faster the experiment is.

`B` and `T` are teaching constants calibrated by the benchmark owner against
the supported environment profiles. This module reads them; it does not choose
them, and neither does a student.

Until they are published, `evaluate` raises. It does not fall back to a
default, and in particular it does not return `revert`: an ungradeable
comparison that returns a decision would award whichever answer happens to be
more common, and would teach a budget nobody stands behind. The Task blocks
instead, and says which gate it is blocked on.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

TASK_ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = TASK_ROOT / "config/adoption-policy.yaml"

KEEP = "keep"
REVERT = "revert"
DECISIONS = (KEEP, REVERT)


class PolicyError(ValueError):
    """Report one actionable problem with the published adoption policy."""


class PolicyUnpublished(PolicyError):
    """Report that the rule's constants are not published yet.

    Separate from `PolicyError` so a check can say "this is a release gate,
    not a mistake you made" rather than reporting a malformed file.
    """


@dataclass(frozen=True)
class AdoptionPolicy:
    """The published rule's calibrated constants and rounding convention."""

    latency_budget_ms: float
    latency_tolerance_ms: float
    recall_places: int
    latency_places: int

    def recall(self, value: float) -> float:
        """Return one recall figure at the published precision."""
        return round(value, self.recall_places)

    def latency(self, value: float) -> float:
        """Return one latency figure at the published precision."""
        return round(value, self.latency_places)


@dataclass(frozen=True)
class RoundingConvention:
    """The published calculation precision, which is readable before B and T are.

    The convention governs how a recorded answer is matched against a retained
    report, and that comparison does not need the rule's constants. Reading it
    separately keeps the numeric answer checks working while the decision check
    is blocked on calibration.
    """

    recall_places: int
    latency_places: int


def _document() -> dict[str, object]:
    """Return the published policy document, or say why it cannot be read."""
    try:
        document = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PolicyError("config/adoption-policy.yaml cannot be read") from exc
    except yaml.YAMLError as exc:
        raise PolicyError("config/adoption-policy.yaml is not valid YAML") from exc
    if not isinstance(document, dict):
        raise PolicyError("config/adoption-policy.yaml must contain one mapping")
    return document


def _places(rounding: object, field: str) -> int:
    """Return one published decimal place count."""
    if not isinstance(rounding, dict):
        raise PolicyError("config/adoption-policy.yaml: `rounding` must be a mapping")
    value = rounding.get(field)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise PolicyError(f"config/adoption-policy.yaml: rounding.{field} must be a place count")
    return value


def rounding() -> RoundingConvention:
    """Return the published rounding convention.

    Available whether or not `B` and `T` are published: matching a recorded
    number against a retained report is a precision question, not a policy one.
    """
    document = _document()
    return RoundingConvention(
        recall_places=_places(document.get("rounding"), "recall_places"),
        latency_places=_places(document.get("rounding"), "latency_places"),
    )


def _constant(document: dict[str, object], field: str) -> float:
    """Return one published, positive policy constant."""
    value = document.get(field)
    if value is None:
        raise PolicyUnpublished(
            f"config/adoption-policy.yaml: {field} is not published yet. The benchmark owner "
            "calibrates it against the supported environment profiles before release; see the "
            "`calibration` block in that file."
        )
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise PolicyError(f"config/adoption-policy.yaml: {field} must be a number")
    if float(value) <= 0.0:
        raise PolicyError(f"config/adoption-policy.yaml: {field} must be positive")
    return float(value)


def published_policy() -> AdoptionPolicy:
    """Return the published rule's constants, or say which gate is unmet.

    Raises `PolicyUnpublished` while the benchmark owner has not calibrated
    `B` and `T`. This local release supplies both; an unavailable policy still blocks.
    """
    document = _document()
    if document.get("published") is not True:
        raise PolicyUnpublished(
            "config/adoption-policy.yaml records `published: false`. The latency budget (B) "
            "and latency tolerance (T) are calibrated and published by the benchmark owner "
            "before release, and until then no adoption decision can be graded. This is a "
            "release gate on the Task, not a mistake in your submission."
        )
    convention = rounding()
    return AdoptionPolicy(
        latency_budget_ms=_constant(document, "latency_budget_ms"),
        latency_tolerance_ms=_constant(document, "latency_tolerance_ms"),
        recall_places=convention.recall_places,
        latency_places=convention.latency_places,
    )


@dataclass(frozen=True)
class Decision:
    """The decision the published rule returns for one valid comparison."""

    decision: str
    reason: str


def decide(
    *,
    baseline_recall: float,
    experiment_recall: float,
    baseline_latency_ms: float,
    experiment_latency_ms: float,
    policy: AdoptionPolicy,
) -> Decision:
    """Return the one decision the published rule gives for this comparison.

    Every figure is taken to the published precision first, so two values that
    are equal at the precision the report publishes are treated as equal here
    too. Without that, a difference in a place the report does not print could
    decide the outcome.
    """
    recall_0 = policy.recall(baseline_recall)
    recall_1 = policy.recall(experiment_recall)
    latency_0 = policy.latency(baseline_latency_ms)
    latency_1 = policy.latency(experiment_latency_ms)
    budget = policy.latency(policy.latency_budget_ms)
    tolerance = policy.latency(policy.latency_tolerance_ms)

    if recall_1 < recall_0:
        return Decision(
            REVERT,
            f"recall fell from {recall_0} to {recall_1}, and the rule never accepts a recall loss",
        )
    if latency_1 > budget:
        return Decision(
            REVERT,
            f"the experiment p95 of {latency_1} ms is above the published budget of {budget} ms",
        )
    if recall_1 > recall_0:
        return Decision(
            KEEP,
            f"recall rose from {recall_0} to {recall_1} and the experiment p95 of {latency_1} "
            f"ms meets the published budget of {budget} ms",
        )
    improvement = policy.latency(latency_0 - latency_1)
    if improvement > tolerance:
        return Decision(
            KEEP,
            f"recall is unchanged at {recall_1}, and the p95 improved by {improvement} ms, "
            f"which exceeds the published tolerance of {tolerance} ms",
        )
    return Decision(
        REVERT,
        f"recall is unchanged at {recall_1}, and the p95 change of {improvement} ms does not "
        f"exceed the published tolerance of {tolerance} ms",
    )


def evaluate(
    *,
    baseline_recall: float,
    experiment_recall: float,
    baseline_latency_ms: float,
    experiment_latency_ms: float,
) -> Decision:
    """Return the published rule's decision, reading its constants as published.

    Raises `PolicyUnpublished` while `B` and `T` are uncalibrated. Callers must
    not turn that into a decision.
    """
    return decide(
        baseline_recall=baseline_recall,
        experiment_recall=experiment_recall,
        baseline_latency_ms=baseline_latency_ms,
        experiment_latency_ms=experiment_latency_ms,
        policy=published_policy(),
    )
