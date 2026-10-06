"""Coldline.

===================

File:              tests/contract/test_reliability_gate.py
Component:         Contract tests — CI reliability gate
Purpose:           Prove the wired reliability-gate job is real and actually gates.
Interacts With:    .github/workflows/task.yml, Docker Compose, LocalStack SQS, Prometheus
Sprint/Task:       Sprint 3 — Project 3
Concepts:          CI reliability gate, assessment integrity, deterministic infrastructure
Tools:             Python 3.12, pytest, PyYAML, boto3, Docker Compose
"""

import pytest

from tests.contract import reliability_gate

pytestmark = pytest.mark.runtime


def test_reliability_gate_runs_a_real_check() -> None:
    """Catch a placeholder left in place, or a replacement that is not exactly one check.

    Static only: no running stack is required to catch these. Rejects a step that still
    prints the supplied placeholder text, a step matching neither `poe queue-contract` nor
    `poe slo-contract`, and a job that wires both at once.
    """
    findings = reliability_gate.static_findings()
    assert not findings, "; ".join(findings)


def test_reliability_gate_rejects_the_known_broken_value() -> None:
    """Catch a wired check that is real but does not actually depend on what it protects.

    Runs the wired command against the current, correctly configured stack (must pass), then
    temporarily reverts the one setting it protects to that setting's own Task's known
    starting-broken value and runs it again (must now fail), then restores the setting. The
    revert and restore always run, including on an assertion failure or an unexpected
    exception; the working tree is unchanged afterward.
    """
    reliability_gate.prove_gate_rejects_broken_value()
