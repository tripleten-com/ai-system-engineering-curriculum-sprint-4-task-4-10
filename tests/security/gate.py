"""Coldline.

===================

File:              tests/security/gate.py
Component:         Security tooling — Gate thresholds
Purpose:           Read security/gate.yaml, validate its three thresholds against the allowed
                    values, decide which findings are at or above them, and state what the gate
                    policy requires of them.
Interacts With:    security/gate.yaml, docs/security/gate-policy.md, tests/security/scanners.py,
                    tests/contract/test_security_contract.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          One severity scale across scanners, report-only versus failing, a policy the
                    file must meet
Tools:             Python 3.12, PyYAML

One threshold per scanner, with the allowed values of each listed here as the file's
comments list them: ``secrets`` is ``none`` or ``any``; ``dependencies`` and
``static_analysis`` are ``none``, ``high`` or ``critical``, the lowest severity on the
gate's scale (``low``, ``medium``, ``high``, ``critical``) that fails the gate. A value
outside the allowed ones is a ``GateError`` naming the key and the allowed values, raised
before anything is scanned. ``policy_findings`` says where a file falls short of
``docs/security/gate-policy.md``: secrets must be ``any``, dependencies must be ``high``,
and static analysis must be one of the failing values.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

TASK_ROOT = Path(__file__).resolve().parents[2]
GATE_PATH = Path("security/gate.yaml")
SEVERITIES: tuple[str, ...] = ("low", "medium", "high", "critical")
SECRET = "secret"
NONE = "none"
ANY = "any"
KEYS: tuple[str, ...] = ("secrets", "dependencies", "static_analysis")
ALLOWED: dict[str, tuple[str, ...]] = {
    "secrets": (NONE, ANY),
    "dependencies": (NONE, "high", "critical"),
    "static_analysis": (NONE, "high", "critical"),
}
# What the policy requires: any secret fails; a high vulnerability fails (so `critical`,
# which lets a high one through, does not meet it); static analysis fails at one of the
# failing values, chosen by the student.
REQUIRED: dict[str, str] = {"secrets": ANY, "dependencies": "high"}
STATIC_CHOICES: tuple[str, ...] = ("high", "critical")
# Which threshold each scanner's findings are judged against.
SCANNER_KEY: dict[str, str] = {
    "gitleaks": "secrets",
    "trivy": "dependencies",
    "semgrep": "static_analysis",
}


class GateError(ValueError):
    """Report that security/gate.yaml is not a valid thresholds file."""


def rank(severity: str) -> int:
    """Return a severity's position on the scale; an unknown severity ranks lowest."""
    return SEVERITIES.index(severity) if severity in SEVERITIES else -1


@dataclass(frozen=True)
class Thresholds:
    """The three thresholds of security/gate.yaml, each one of its allowed values."""

    secrets: str
    dependencies: str
    static_analysis: str

    def value(self, key: str) -> str:
        """Return the threshold named ``key`` (one of ``KEYS``)."""
        return str(getattr(self, key))

    def fails(self, scanner: str, severity: str) -> bool:
        """Return whether a finding of this scanner and severity is at or above its threshold."""
        key = SCANNER_KEY.get(scanner)
        if key is None:
            return False
        threshold = self.value(key)
        if threshold == NONE:
            return False
        if key == "secrets":
            return severity == SECRET
        return rank(severity) >= rank(threshold)

    def describe(self) -> str:
        """Return the thresholds as one line, for the scan's header."""
        return ", ".join(f"{key}={self.value(key)}" for key in KEYS)


def thresholds_from(document: object, *, source: str = GATE_PATH.as_posix()) -> Thresholds:
    """Validate one loaded document as the thresholds file."""
    if not isinstance(document, dict):
        raise GateError(f"{source} must be one mapping with the keys {', '.join(KEYS)}")
    unknown = sorted(str(key) for key in document if key not in KEYS)
    if unknown:
        raise GateError(f"{source} names keys the gate does not read: {', '.join(unknown)}")
    values: dict[str, str] = {}
    for key in KEYS:
        if key not in document:
            raise GateError(f"{source} is missing the threshold `{key}`")
        value = document[key]
        allowed = ", ".join(ALLOWED[key])
        if not isinstance(value, str) or value not in ALLOWED[key]:
            raise GateError(
                f"{source}: `{key}` is {value!r}; the allowed values are {allowed} (see the "
                "comments beside the key)"
            )
        values[key] = value
    return Thresholds(values["secrets"], values["dependencies"], values["static_analysis"])


def load_thresholds(path: Path | None = None, *, root: Path = TASK_ROOT) -> Thresholds:
    """Read and validate security/gate.yaml (or ``path``)."""
    target = root / GATE_PATH if path is None else path
    try:
        document = yaml.safe_load(target.read_text(encoding="utf-8"))
    except OSError as exc:
        raise GateError(f"{GATE_PATH.as_posix()} could not be read: {exc}") from exc
    except yaml.YAMLError as exc:
        raise GateError(f"{GATE_PATH.as_posix()} is not valid YAML: {exc}") from exc
    return thresholds_from(document)


def policy_findings(thresholds: Thresholds) -> list[str]:
    """Return where the thresholds fall short of docs/security/gate-policy.md."""
    findings: list[str] = []
    for key, required in REQUIRED.items():
        if thresholds.value(key) != required:
            findings.append(
                f"`{key}` is {thresholds.value(key)}; the gate policy requires `{required}` "
                + (
                    "(any unsuppressed secret finding fails the gate)"
                    if key == "secrets"
                    else "(a known high-severity vulnerability fails the gate)"
                )
            )
    if thresholds.static_analysis not in STATIC_CHOICES:
        findings.append(
            f"`static_analysis` is {thresholds.static_analysis}; the gate policy requires one "
            f"of the failing values ({', '.join(STATIC_CHOICES)}), chosen by you"
        )
    return findings


__all__ = [
    "ALLOWED",
    "ANY",
    "GATE_PATH",
    "KEYS",
    "NONE",
    "REQUIRED",
    "SCANNER_KEY",
    "SECRET",
    "SEVERITIES",
    "STATIC_CHOICES",
    "GateError",
    "Thresholds",
    "load_thresholds",
    "policy_findings",
    "rank",
    "thresholds_from",
]
