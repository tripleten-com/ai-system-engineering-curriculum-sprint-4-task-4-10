"""Coldline.

===================

File:              tests/unit/security/test_gate.py
Component:         Unit tests — Gate thresholds
Purpose:           Prove the thresholds file is validated against its allowed values, that each
                    scanner's findings are judged against the right threshold on one scale, and
                    that the policy's requirements are stated as findings.
Interacts With:    tests/security/gate.py, security/gate.yaml
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          One severity scale, report-only versus failing
Tools:             Python 3.12, pytest

The shipped security/gate.yaml is student-editable and is not read here; every document is
synthetic.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.security import gate


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "gate.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_a_report_only_file_loads_and_fails_nothing(tmp_path: Path) -> None:
    """Every threshold `none` is valid and marks no finding."""
    thresholds = gate.load_thresholds(
        _write(tmp_path, "secrets: none\ndependencies: none\nstatic_analysis: none\n")
    )

    assert thresholds == gate.Thresholds("none", "none", "none")
    for scanner, severity in (("gitleaks", "secret"), ("trivy", "critical"), ("semgrep", "high")):
        assert not thresholds.fails(scanner, severity)
    assert thresholds.describe() == "secrets=none, dependencies=none, static_analysis=none"


@pytest.mark.parametrize(
    "text, message",
    [
        ("secrets: always\ndependencies: high\nstatic_analysis: high\n", "`secrets` is 'always'"),
        (
            "secrets: any\ndependencies: medium\nstatic_analysis: high\n",
            "`dependencies` is 'medium'",
        ),
        ("secrets: any\ndependencies: high\nstatic_analysis: low\n", "`static_analysis` is 'low'"),
        ("secrets: any\ndependencies: high\n", "missing the threshold `static_analysis`"),
        (
            "secrets: any\ndependencies: high\nstatic_analysis: high\nimages: high\n",
            "does not read",
        ),
        ("- secrets\n", "must be one mapping"),
        ("secrets: any\ndependencies: high\nstatic_analysis: [high]\n", "`static_analysis` is"),
    ],
    ids=["secrets", "dependencies", "static", "missing", "unknown-key", "not-a-mapping", "list"],
)
def test_values_outside_the_allowed_ones_are_named_with_the_allowed_values(
    tmp_path: Path, text: str, message: str
) -> None:
    """A wrong value names the key and lists the allowed values; a wrong shape names the shape."""
    with pytest.raises(gate.GateError, match=message):
        gate.load_thresholds(_write(tmp_path, text))


def test_each_scanner_is_judged_against_its_own_threshold_on_one_scale() -> None:
    """Secrets fail on `any`; the other two fail at or above the named severity."""
    thresholds = gate.Thresholds("any", "high", "critical")

    assert thresholds.fails("gitleaks", gate.SECRET)
    assert thresholds.fails("trivy", "high") and thresholds.fails("trivy", "critical")
    assert not thresholds.fails("trivy", "medium")
    assert thresholds.fails("semgrep", "critical")
    assert not thresholds.fails("semgrep", "high") and not thresholds.fails("semgrep", "medium")
    assert not thresholds.fails("unknown-scanner", "critical")
    assert gate.rank("low") < gate.rank("medium") < gate.rank("high") < gate.rank("critical")
    assert gate.rank("unknown") == -1


def test_the_policy_requires_any_secret_a_high_dependency_and_a_failing_static_value() -> None:
    """`policy_findings` names each shortfall; a compliant file has none, whichever static value."""
    assert gate.policy_findings(gate.Thresholds("any", "high", "high")) == []
    assert gate.policy_findings(gate.Thresholds("any", "high", "critical")) == []

    findings = gate.policy_findings(gate.Thresholds("none", "critical", "none"))
    assert len(findings) == 3
    assert findings[0].startswith("`secrets` is none; the gate policy requires `any`")
    assert findings[1].startswith("`dependencies` is critical; the gate policy requires `high`")
    assert "`static_analysis` is none" in findings[2]


def test_the_allowed_values_match_the_keys_the_file_names() -> None:
    """The three keys, their allowed values, and the scanner mapping agree with each other."""
    assert gate.KEYS == ("secrets", "dependencies", "static_analysis")
    assert set(gate.ALLOWED) == set(gate.KEYS)
    assert gate.ALLOWED["secrets"] == ("none", "any")
    assert gate.ALLOWED["dependencies"] == ("none", "high", "critical")
    assert gate.ALLOWED["static_analysis"] == ("none", "high", "critical")
    assert set(gate.SCANNER_KEY.values()) == set(gate.KEYS)
    assert gate.REQUIRED == {"secrets": "any", "dependencies": "high"}
    assert gate.STATIC_CHOICES == ("high", "critical")
