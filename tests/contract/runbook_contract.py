"""Coldline.

===================

File:              tests/contract/runbook_contract.py
Component:         Contract tests — Runbook structure
Purpose:           Check that docs/student/runbook.md exists with its four required sections.
Interacts With:    docs/student/runbook.md
Sprint/Task:       Sprint 3 — Project 3
Concepts:          Recovery runbook, deterministic assessment, structure not prose
Tools:             Python 3.12

This module is a ``findings()``-style checker in the same spirit as
``tests/contract/reliability_gate.py``'s static half. It reads one student-written
Markdown file and reports every structural reason it is not yet a complete runbook:

- the file does not exist;
- one of the four required level-two headings is missing, misspelled, or repeated;
- the headings are present but out of order;
- a section carries no content of its own (nothing between its heading and the next).

It deliberately grades nothing about the prose. What a student wrote in each section is
for the Task 3.7 Project Defense; this check only guarantees there is a runbook, with the
four parts a bounded detection-to-verification runbook must have, for that conversation to
be about.
"""

from __future__ import annotations

import sys
from pathlib import Path

TASK_ROOT = Path(__file__).resolve().parents[2]
RUNBOOK_PATH = TASK_ROOT / "docs/student/runbook.md"
# Exact, case-sensitive, whole-line headings, in this order. Documented verbatim in
# docs/student/task-3-6-contract.md; a change here is a contract change.
REQUIRED_HEADINGS = (
    "## Detection",
    "## Diagnosis",
    "## Recovery",
    "## Verification",
)


def findings(path: Path = RUNBOOK_PATH) -> list[str]:
    """Return every reason the runbook is not yet structurally complete, or an empty list."""
    if not path.is_file():
        return [f"{_display(path)} does not exist"]
    lines = path.read_text(encoding="utf-8").splitlines()
    stripped = [line.rstrip() for line in lines]
    failures: list[str] = []

    positions: dict[str, list[int]] = {heading: [] for heading in REQUIRED_HEADINGS}
    for index, line in enumerate(stripped):
        if line in positions:
            positions[line].append(index)
    for heading in REQUIRED_HEADINGS:
        count = len(positions[heading])
        if count == 0:
            failures.append(f"required heading is missing: {heading!r}")
        elif count > 1:
            failures.append(f"required heading appears {count} times, expected once: {heading!r}")
    if failures:
        return failures

    ordered = [positions[heading][0] for heading in REQUIRED_HEADINGS]
    if ordered != sorted(ordered):
        failures.append(
            "required headings are out of order; expected " + ", ".join(REQUIRED_HEADINGS)
        )

    for heading, start in zip(REQUIRED_HEADINGS, ordered, strict=True):
        end = _next_heading_index(stripped, start)
        body = [line for line in stripped[start + 1 : end] if line.strip()]
        if not any(not line.startswith("#") for line in body):
            failures.append(f"section has no content of its own: {heading!r}")
    return failures


def _next_heading_index(lines: list[str], start: int) -> int:
    """Return the index of the next level-one or level-two heading after ``start``."""
    for index in range(start + 1, len(lines)):
        if lines[index].startswith(("# ", "## ")):
            return index
    return len(lines)


def _display(path: Path) -> str:
    """Name a path relative to the Task root when it lives there, else as given."""
    try:
        return path.relative_to(TASK_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


if __name__ == "__main__":
    problems = findings()
    if problems:
        print("Runbook findings:", file=sys.stderr)
        for problem in problems:
            print(f"- {problem}", file=sys.stderr)
        sys.exit(1)
    print("Runbook verification passed: all four required sections are present with content.")
