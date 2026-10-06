"""Coldline.

===================

File:              tests/benchmark/reports.py
Component:         Benchmark — Retained arm reports
Purpose:           Capture, retain, and validate the reports a decision is graded against.
Interacts With:    tests/benchmark/runner.py, config/benchmark-template.yaml, the report contract
Sprint/Task:       Sprint 2 — Project 2 / Task 2.7
Concepts:          Report provenance, write-once retention, consistency validation
Tools:             Python 3.12, jsonschema, PyYAML

The recorded answers and the adoption decision are graded against these two
retained reports, not against a fresh measurement. That is the point: a
measurement taken now cannot be the evidence for a decision recorded earlier,
and re-measuring at grading time would quietly replace the inputs that decision
was made from.

So each arm is captured by its own command and written once:

    .benchmark/baseline.json      written by `poe benchmark-baseline`
    .benchmark/experiment.json    written by `poe benchmark-experiment`

An experiment capture never writes the baseline path — enforced here and
checked by a test. Recapturing the baseline discards the experiment report with
it, because a baseline from one moment and an experiment from another are not a
comparison.

What validation can and cannot do
---------------------------------

It can establish *consistency*: that a report matches this contract, names this
template and this pinned measurement procedure, ran against the live golden
set, describes the configuration it claims to, and agrees with its own per-query
rows. Those checks catch a stale report, a report from another checkout, a
report for a configuration that has since been edited, and a report whose
totals were changed by hand.

It cannot authenticate a wall-clock measurement. A report edited into a
self-consistent whole is indistinguishable from a measured one here, and
nothing in this module pretends otherwise. Detecting that would need a signing
service this Task does not have and does not introduce.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

from tests.benchmark.config import RetrievalConfig, baseline_config
from tests.benchmark.metrics import mean, rounded
from tests.benchmark.runner import ArmReport, golden_set_digest

TASK_ROOT = Path(__file__).resolve().parents[2]
REPORT_DIRECTORY = TASK_ROOT / ".benchmark"
REPORT_CONTRACT = TASK_ROOT / "docs/contracts/benchmark-report.schema.json"
TEMPLATE_PATH = TASK_ROOT / "config/benchmark-template.yaml"

BASELINE_ARM = "baseline"
EXPERIMENT_ARM = "experiment"
ARMS = (BASELINE_ARM, EXPERIMENT_ARM)

REPORT_SCHEMA_VERSION = 1
# Overrides where the reports are read from and written to. The assessed checks
# use it to validate a prepared pair without touching a student's own captures.
REPORT_DIRECTORY_OVERRIDE = "COLDLINE_BENCHMARK_REPORTS"


class ReportError(ValueError):
    """Report one actionable problem with a retained benchmark report.

    Raised for a missing, malformed, stale, or self-inconsistent report. It is
    never converted into a decision: an invalid comparison fails validation
    rather than defaulting to `revert`, because defaulting would award whichever
    answer happens to be more common.
    """


def report_directory() -> Path:
    """Return the directory the retained reports live in."""
    override = os.environ.get(REPORT_DIRECTORY_OVERRIDE, "")
    return Path(override) if override else REPORT_DIRECTORY


def report_path(arm: str) -> Path:
    """Return the published path of one arm's retained report."""
    if arm not in ARMS:
        raise ReportError(f"arm must be one of {list(ARMS)}; found {arm!r}")
    return report_directory() / f"{arm}.json"


def template_identity() -> tuple[str, int]:
    """Return the supplied template identifier and pinned harness version."""
    try:
        document = yaml.safe_load(TEMPLATE_PATH.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ReportError("config/benchmark-template.yaml cannot be read") from exc
    except yaml.YAMLError as exc:
        raise ReportError("config/benchmark-template.yaml is not valid YAML") from exc
    if not isinstance(document, dict):
        raise ReportError("config/benchmark-template.yaml must contain one mapping")
    template_id = document.get("template_id")
    harness_version = document.get("harness_version")
    if not isinstance(template_id, str) or not template_id:
        raise ReportError("config/benchmark-template.yaml: template_id must be a name")
    if not isinstance(harness_version, int) or isinstance(harness_version, bool):
        raise ReportError("config/benchmark-template.yaml: harness_version must be a whole number")
    return template_id, harness_version


def configuration_id(config: dict[str, float]) -> str:
    """Return the digest that identifies one measured retrieval configuration."""
    canonical = json.dumps(config, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def as_document(report: ArmReport) -> dict[str, Any]:
    """Return one measured arm as a retainable report document with its provenance."""
    template_id, harness_version = template_identity()
    document = report.as_document()
    document.pop("latency_tolerance_ms", None)
    document.update(
        {
            "report_schema_version": REPORT_SCHEMA_VERSION,
            "harness_version": harness_version,
            "template_id": template_id,
            "fixture_id": report.golden_set_digest,
            "configuration_id": configuration_id(report.config),
            "run_id": uuid.uuid4().hex,
            "captured_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    )
    return document


def retain(report: ArmReport, *, recapture: bool = False) -> Path:
    """Write one arm's report to its published path, once.

    An existing report for the same arm is kept unless ``recapture`` says
    otherwise, so a second run cannot silently replace the evidence an already
    recorded answer was read from. Recapturing the baseline also discards the
    experiment report: a baseline measured now and an experiment measured
    before it are not a comparison, and keeping the pair would look like one.
    """
    directory = report_directory()
    path = directory / f"{report.arm}.json"
    if path.exists() and not recapture:
        raise ReportError(
            f"{path.name} already exists. It is the retained evidence for whatever is "
            f"recorded in submission.yaml, so it is not overwritten by default. Re-run with "
            f"--recapture to discard it and measure again."
        )
    directory.mkdir(parents=True, exist_ok=True)
    if report.arm == BASELINE_ARM:
        stale = directory / f"{EXPERIMENT_ARM}.json"
        if stale.exists():
            stale.unlink()
    path.write_text(
        json.dumps(as_document(report), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return path


@dataclass(frozen=True)
class RetainedReport:
    """One validated retained report, in the terms the checks and the rule use."""

    arm: str
    document: dict[str, Any]

    @property
    def recall_at_k(self) -> float:
        """Return the arm's mean deterministic Recall@K."""
        return float(self.document["recall_at_k"])

    @property
    def judge_relevance(self) -> float:
        """Return the arm's mean cached-judge relevance."""
        return float(self.document["judge_relevance"])

    @property
    def judge_faithfulness(self) -> float:
        """Return the arm's mean cached-judge faithfulness."""
        return float(self.document["judge_faithfulness"])

    @property
    def latency_p50_ms(self) -> float:
        """Return the arm's median query latency."""
        return float(self.document["latency_p50_ms"])

    @property
    def latency_p95_ms(self) -> float:
        """Return the arm's 95th-percentile query latency."""
        return float(self.document["latency_p95_ms"])

    @property
    def latency_p99_ms(self) -> float:
        """Return the arm's 99th-percentile query latency."""
        return float(self.document["latency_p99_ms"])

    @property
    def config(self) -> dict[str, float]:
        """Return the retrieval configuration this arm measured."""
        return dict(self.document["config"])

    @property
    def run_id(self) -> str:
        """Return the capture that produced this report."""
        return str(self.document["run_id"])

    @property
    def fixture_id(self) -> str:
        """Return the golden evaluation set this arm ran against."""
        return str(self.document["fixture_id"])

    @property
    def query_ids(self) -> list[str]:
        """Return the measured queries, in published order."""
        return [str(value) for value in self.document["query_ids"]]

    @property
    def retrieved(self) -> dict[str, list[str]]:
        """Return what each measured query retrieved."""
        return {
            str(row["query_id"]): [str(chunk) for chunk in row["retrieved_chunk_ids"]]
            for row in self.document["queries"]
        }


def _validate_against_contract(arm: str, document: Any) -> None:
    """Reject a report the supplied contract does not accept."""
    schema = json.loads(REPORT_CONTRACT.read_text(encoding="utf-8"))
    errors = sorted(
        Draft202012Validator(schema).iter_errors(document), key=lambda error: list(error.path)
    )
    if errors:
        error = errors[0]
        location = ".".join(str(part) for part in error.absolute_path) or "report"
        raise ReportError(
            f"{arm}.json does not match the report contract: {location}: {error.message}"
        )


def _validate_identifiers(arm: str, document: dict[str, Any]) -> None:
    """Reject a report that names another template, arm, or measurement procedure."""
    template_id, harness_version = template_identity()
    if document["template_id"] != template_id:
        raise ReportError(
            f"{arm}.json was produced by template {document['template_id']!r}, not by "
            f"{template_id!r}. A report from another template is not evidence about this one."
        )
    if document["harness_version"] != harness_version:
        raise ReportError(
            f"{arm}.json was produced by harness version {document['harness_version']}, and "
            f"this template pins version {harness_version}. Re-capture both arms."
        )
    if document["arm"] != arm:
        raise ReportError(f"{arm}.json records the {document['arm']!r} arm")
    if document["failed_query_ids"]:
        raise ReportError(
            f"{arm}.json records failed queries {document['failed_query_ids']}, so it is not "
            "a valid basis for a decision. Fix the failure and capture the arm again."
        )
    if document["configuration_id"] != configuration_id(dict(document["config"])):
        raise ReportError(
            f"{arm}.json carries a configuration identifier that is not the digest of the "
            "configuration it records"
        )
    if document["golden_set_digest"] != document["fixture_id"]:
        raise ReportError(f"{arm}.json disagrees with itself about which fixtures it measured")


def _validate_self_consistency(arm: str, document: dict[str, Any]) -> None:
    """Reject a report whose aggregates disagree with its own per-query rows."""
    rows = document["queries"]
    if [str(row["query_id"]) for row in rows] != [str(value) for value in document["query_ids"]]:
        raise ReportError(f"{arm}.json measures queries its own query_ids field does not list")
    for row in rows:
        if row["relevant_retrieved"] > row["total_relevant"]:
            raise ReportError(
                f"{arm}.json: query {row['query_id']} retrieved more relevant chunks than are "
                "labelled"
            )
        expected = rounded(float(row["relevant_retrieved"]) / float(row["total_relevant"]))
        if rounded(float(row["recall"])) != expected:
            raise ReportError(
                f"{arm}.json: query {row['query_id']} records recall {row['recall']}, and its "
                f"own counts give {expected}"
            )
    aggregate = rounded(mean([float(row["recall"]) for row in rows]))
    if rounded(document["recall_at_k"]) != aggregate:
        raise ReportError(
            f"{arm}.json records recall_at_k {document['recall_at_k']}, and the mean of its own "
            f"per-query rows is {aggregate}"
        )
    p50, p95, p99 = (
        float(document["latency_p50_ms"]),
        float(document["latency_p95_ms"]),
        float(document["latency_p99_ms"]),
    )
    if not p50 <= p95 <= p99:
        raise ReportError(
            f"{arm}.json records percentiles that are not ordered: p50 {p50}, p95 {p95}, p99 {p99}"
        )


def load(arm: str, *, directory: Path | None = None) -> RetainedReport:
    """Return one validated retained report, or say exactly what is wrong with it."""
    path = report_path(arm)
    if directory is not None:
        path = directory / path.name
    if not path.is_file():
        raise ReportError(
            f"{path.name} is missing. Capture it with `poe benchmark-{arm}`; the checks grade "
            "the recorded answers against the retained reports, so there is nothing to grade "
            "without it."
        )
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReportError(f"{path.name} is not readable JSON: {exc}") from exc

    _validate_against_contract(arm, document)
    _validate_identifiers(arm, document)
    _validate_self_consistency(arm, document)
    return RetainedReport(arm=arm, document=document)


def load_pair(*, directory: Path | None = None) -> tuple[RetainedReport, RetainedReport]:
    """Return both validated retained reports, checked as a comparable pair.

    Each report is valid on its own before this compares them, so a failure
    here is always about the pair rather than about one arm.
    """
    baseline, experiment = (
        load(BASELINE_ARM, directory=directory),
        load(EXPERIMENT_ARM, directory=directory),
    )
    if baseline.fixture_id != experiment.fixture_id:
        raise ReportError(
            "the two retained reports ran against different golden evaluation sets, so they "
            "are not a comparison. Capture both arms again."
        )
    live = golden_set_digest()
    if baseline.fixture_id != live:
        raise ReportError(
            "the retained reports ran against a golden evaluation set that is no longer the "
            "one in this checkout. Capture both arms again."
        )
    if baseline.run_id == experiment.run_id:
        raise ReportError(
            "both retained reports carry the same run identifier, so they are one capture "
            "presented as two. Capture each arm with its own command."
        )
    if baseline.query_ids != experiment.query_ids:
        raise ReportError("the two retained reports measured different queries")
    supplied = baseline_config()
    if baseline.config != supplied.as_mapping():
        raise ReportError(
            f"the baseline report measured {baseline.config}, and the supplied baseline is "
            f"{supplied.as_mapping()}. The baseline arm must measure the supplied "
            "configuration; capture it again."
        )
    if baseline.config == experiment.config:
        raise ReportError(
            "both retained reports measured the same configuration, so no experiment was run. "
            "Change one approved parameter in config/student/retrieval.yaml and capture the "
            "experiment arm again."
        )
    return baseline, experiment


def measured_configuration(report: RetainedReport) -> RetrievalConfig:
    """Return one report's measured configuration in the harness's own type."""
    config = report.config
    return RetrievalConfig(top_k=int(config["top_k"]), fusion_weight=float(config["fusion_weight"]))


def impacted_query_ids(baseline: RetainedReport, experiment: RetainedReport) -> list[str]:
    """Return the published queries whose retrieved ranking the change moved."""
    before, after = baseline.retrieved, experiment.retrieved
    return [query_id for query_id in baseline.query_ids if before[query_id] != after[query_id]]
