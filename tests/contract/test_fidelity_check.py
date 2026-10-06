"""Coldline.

===================

File:              tests/contract/test_fidelity_check.py
Component:         Contract tests — Fidelity record structure
Purpose:           Require the JobQueue fidelity record to carry the ECS fidelity section.
Interacts With:    docs/fidelity/JobQueue.md
Sprint/Task:       Sprint 3 — Project 3
Concepts:          Fidelity limits, managed ECS versus Compose, structure not prose
Tools:             Python 3.12, pytest
"""

import pytest

from tests.contract import fidelity_check

# Assessed, not runtime: no stack is needed, and a fresh starter inherits Task 3.3's
# record without the ECS section, so this is expected to fail until the student adds it.
# `poe contract` deselects it; `poe fidelity-check` and `poe verify` run it.
pytestmark = pytest.mark.assessed


def test_fidelity_record_states_the_ecs_limits() -> None:
    """Catch a missing ECS section, a missing required code, or a removed SQS statement.

    Static only. Rejects a `docs/fidelity/JobQueue.md` that lost Task 3.3's own SQS limits
    statement, that lacks the `## ECS fidelity limits (Task 3.6)` heading, or whose section
    does not carry each of `ECS-01`..`ECS-04` on a line of the documented form. Grades
    nothing about the reasoning behind any code.
    """
    findings = fidelity_check.findings()
    assert not findings, "; ".join(findings)
