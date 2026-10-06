"""Coldline.

===================

File:              tests/benchmark/config.py
Component:         Benchmark — Retrieval configuration
Purpose:           Load and compare the baseline and experimental retrieval configurations.
Interacts With:    config/retrieval-baseline.yaml and config/student/retrieval.yaml
Sprint/Task:       Sprint 2 — Project 2 / Task 2.7
Concepts:          Single-variable change, validated configuration
Tools:             Python 3.12, PyYAML
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

TASK_ROOT = Path(__file__).resolve().parents[2]
BASELINE_PATH = TASK_ROOT / "config/retrieval-baseline.yaml"
STUDENT_PATH = TASK_ROOT / "config/student/retrieval.yaml"
# Points the harness and the regression helper at a different configuration
# file. The assessed checks use it to measure a configuration without editing a
# student's own file.
CONFIG_OVERRIDE = "COLDLINE_RETRIEVAL_CONFIG"

# The retriever fetches a fixed pool of candidates from each arm before fusion,
# so `top_k` above that could never be satisfied and is rejected rather than
# silently clamped. Keep this equal to
# `adapters.retriever.postgres_hybrid.CANDIDATE_POOL`.
CANDIDATE_POOL = 12
APPROVED_PARAMETERS = ("top_k", "fusion_weight")


class ConfigurationError(ValueError):
    """Report one actionable retrieval-configuration problem."""


@dataclass(frozen=True)
class RetrievalConfig:
    """One validated retrieval configuration."""

    top_k: int
    fusion_weight: float

    def as_mapping(self) -> dict[str, float]:
        """Return the configuration as a plain mapping, for reports."""
        return {"top_k": self.top_k, "fusion_weight": self.fusion_weight}


def load_config(path: Path) -> RetrievalConfig:
    """Load one retrieval configuration file, rejecting anything unexpected.

    The validation is strict on purpose. This Task is a controlled experiment,
    and a configuration that quietly ignored a misspelled key, or accepted a
    value the retriever cannot honor, would produce a measurement that looks
    valid and means nothing.
    """
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigurationError(f"{path.name} cannot be read") from exc
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"{path.name} is not valid YAML") from exc

    if not isinstance(document, dict) or set(document) != {"retrieval"}:
        raise ConfigurationError(
            f"{path.name} must contain exactly one top-level `retrieval` mapping"
        )
    retrieval = document["retrieval"]
    if not isinstance(retrieval, dict):
        raise ConfigurationError(f"{path.name}: `retrieval` must be a mapping")
    unknown = sorted(set(retrieval) - set(APPROVED_PARAMETERS))
    missing = sorted(set(APPROVED_PARAMETERS) - set(retrieval))
    if unknown:
        raise ConfigurationError(f"{path.name}: unapproved parameters {unknown}")
    if missing:
        raise ConfigurationError(f"{path.name}: missing parameters {missing}")

    return RetrievalConfig(
        top_k=_top_k(path, retrieval["top_k"]),
        fusion_weight=_fusion_weight(path, retrieval["fusion_weight"]),
    )


def _top_k(path: Path, value: Any) -> int:
    """Validate the candidate count."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise ConfigurationError(f"{path.name}: top_k must be a whole number")
    if not 1 <= value <= CANDIDATE_POOL:
        raise ConfigurationError(
            f"{path.name}: top_k must be between 1 and {CANDIDATE_POOL}, the fixed candidate "
            f"pool each arm fetches before fusion; found {value}"
        )
    return value


def _fusion_weight(path: Path, value: Any) -> float:
    """Validate the dense-arm fusion weight."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ConfigurationError(f"{path.name}: fusion_weight must be a number")
    if not 0.0 <= float(value) <= 1.0:
        raise ConfigurationError(
            f"{path.name}: fusion_weight must be between 0.0 and 1.0; found {value}"
        )
    return float(value)


def baseline_config() -> RetrievalConfig:
    """Return the protected baseline configuration."""
    return load_config(BASELINE_PATH)


def experiment_config() -> RetrievalConfig:
    """Return the experimental configuration, honoring the documented override."""
    override = os.environ.get(CONFIG_OVERRIDE, "")
    return load_config(Path(override) if override else STUDENT_PATH)


def changed_parameter(baseline: RetrievalConfig, experiment: RetrievalConfig) -> tuple[str, float]:
    """Return the single parameter that differs, or fail with what went wrong.

    Exactly one approved parameter may differ. Zero means no experiment was
    run; two means the change was not controlled and neither result can be
    attributed to either parameter.
    """
    changed = [
        name for name in APPROVED_PARAMETERS if getattr(baseline, name) != getattr(experiment, name)
    ]
    if not changed:
        raise ConfigurationError(
            "config/student/retrieval.yaml is still identical to the baseline: no parameter "
            "has been tuned yet"
        )
    if len(changed) > 1:
        raise ConfigurationError(
            f"exactly one approved parameter may change; these differ from the baseline: "
            f"{changed}. With two variables moving, neither measured shift can be attributed "
            "to either one."
        )
    name = changed[0]
    return name, float(getattr(experiment, name))
