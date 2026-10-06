"""Coldline.

===================

File:              tests/unit/security/test_redaction_report.py
Component:         Unit tests — Redaction report
Purpose:           Prove `poe redaction-report` prints every supplied note's original, redacted
                    text and marked values, names the redactor's version, and judges no note.
Interacts With:    tests/security/redaction_report.py, tests/security/pii.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.4
Concepts:          Evidence laid out for a reader's judgement
Tools:             Python 3.12, pytest
"""

from __future__ import annotations

from pathlib import Path

import pytest

from common.redactor import REDACTOR_VERSION
from tests.security import pii, redaction_report

TASK_ROOT = Path(__file__).resolve().parents[3]


def test_the_report_names_the_version_and_every_note_and_prints_no_verdict(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The command's output is the header plus `pii.report_lines`, nothing judged."""
    assert redaction_report.main(["--root", str(TASK_ROOT)]) == 0

    out = capsys.readouterr().out
    notes = pii.load_notes(TASK_ROOT)
    assert out.startswith(f"# Redaction report: redactor {REDACTOR_VERSION}, {len(notes)} ")
    for note in notes.values():
        assert f"## {note.note_id}\n" in out
        assert f"original: {note.text}\n" in out
    assert out.count("redacted: ") == len(notes)
    assert out.count("marked:   ") == len(notes)
    assert "\n".join(pii.report_lines(notes)) in out
    lowered = out.lower()
    for verdict in ("mishandled", "wrong", "false_negative", "false_positive", "rl-"):
        assert verdict not in lowered, verdict
