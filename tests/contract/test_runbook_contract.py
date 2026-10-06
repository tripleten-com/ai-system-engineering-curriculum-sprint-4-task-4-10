"""Coldline.

===================

File:              tests/contract/test_runbook_contract.py
Component:         Contract tests — Runbook structure
Purpose:           Require the student's runbook to exist with its four required sections.
Interacts With:    docs/student/runbook.md
Sprint/Task:       Sprint 3 — Project 3
Concepts:          Recovery runbook, deterministic assessment, structure not prose
Tools:             Python 3.12, pytest
"""

import pytest

from tests.contract import runbook_contract

# Assessed, not runtime: no stack is needed, and a fresh starter has no runbook yet, so
# this is expected to fail until the student writes one. `poe contract` deselects it;
# `poe runbook-contract` and `poe verify` run it.
pytestmark = pytest.mark.assessed


def test_runbook_has_the_required_sections() -> None:
    """Catch a missing runbook, a missing or repeated heading, or an empty section.

    Static only. Rejects an absent `docs/student/runbook.md`; a `## Detection`,
    `## Diagnosis`, `## Recovery`, or `## Verification` heading that is missing, misspelled,
    duplicated, or out of order; and a section with no line of its own under it. Grades
    nothing about what the sections say.
    """
    findings = runbook_contract.findings()
    assert not findings, "; ".join(findings)
