"""Coldline.

===================

File:              tests/security/redaction_report.py
Component:         Security tooling — Redaction report
Purpose:           Print, for every supplied note, the original text, the redactor's output and
                    the values the fixture marks, so the two can be compared by hand.
Interacts With:    tests/fixtures/pii/notes.yaml, src/common/redactor.py, tests/security/pii.py,
                    pyproject.toml (`poe redaction-report`)
Sprint/Task:       Sprint 4 — Project 4 / Task 4.4
Concepts:          Evidence laid out for a reader's judgement, no verdict in the tooling
Tools:             Python 3.12

``poe redaction-report`` needs no running stack. It prints three lines per note and stops:
which note's redacted text disagrees with its marked values, and how, is the reader's
finding, recorded in ``submission.yaml``. The report names no note as right or wrong.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from common.redactor import REDACTOR_VERSION
from tests.security import pii


def main(argv: Sequence[str] | None = None) -> int:
    """Print the report for every supplied note."""
    parser = argparse.ArgumentParser(
        description="Print each supplied note, its redaction, and its marked values."
    )
    parser.add_argument("--root", type=Path, default=pii.TASK_ROOT)
    arguments = parser.parse_args(argv)
    notes = pii.load_notes(arguments.root)
    print(f"# Redaction report: redactor {REDACTOR_VERSION}, {len(notes)} supplied notes")
    print()
    for line in pii.report_lines(notes):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
