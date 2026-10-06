"""Coldline.

===================

File:              tests/contract/fidelity_check.py
Component:         Contract tests — Fidelity record structure
Purpose:           Check that docs/fidelity/JobQueue.md carries the required ECS fidelity section.
Interacts With:    docs/fidelity/JobQueue.md
Sprint/Task:       Sprint 3 — Project 3
Concepts:          Fidelity limits, managed ECS versus Compose, structure not prose
Tools:             Python 3.12

Task 3.3's record already states what LocalStack SQS does not prove about managed SQS. Task
3.6 asks the student to add, in the same file, what stopping and starting one Compose
``worker`` container does not prove about the same worker running as an Amazon ECS service.
This module reports every structural reason that addition is not yet complete:

- the file is missing, or Task 3.3's own SQS limits statement was removed;
- the required ``## ECS fidelity limits (Task 3.6)`` heading is missing or repeated;
- a required ``ECS-0N`` code does not appear inside that section on a line of the
  documented form (optionally a list bullet, optionally bold, then the code, a colon, and
  at least one word).

It deliberately grades nothing about the reasoning behind each code. The depth of a
student's ECS limitations is for the Task 3.7 Project Defense.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

TASK_ROOT = Path(__file__).resolve().parents[2]
FIDELITY_PATH = TASK_ROOT / "docs/fidelity/JobQueue.md"
# Exact, whole-line heading. Documented verbatim in docs/student/task-3-6-contract.md.
REQUIRED_HEADING = "## ECS fidelity limits (Task 3.6)"
# Each required code names one concrete thing a Compose container stop/start cannot show
# about an ECS service: placement, scheduler-driven replacement, autoscaling, and
# health-check grace / load-balancer behaviour. Documented in the Task contract.
REQUIRED_CODES = ("ECS-01", "ECS-02", "ECS-03", "ECS-04")
# Task 3.3's own statement of the SQS limits. It has to survive the student's edit: the
# ECS section extends the record, it does not replace it.
INHERITED_SQS_STATEMENT = "This local implementation does not claim IAM enforcement"


def _code_pattern(code: str) -> re.Pattern[str]:
    """Return the documented line form for one limitation code."""
    return re.compile(rf"^\s*(?:[-*]\s+)?(?:\*\*)?{re.escape(code)}(?:\*\*)?\s*:\s*\S")


def findings(path: Path = FIDELITY_PATH) -> list[str]:
    """Return every reason the fidelity record is not yet structurally complete, or []."""
    if not path.is_file():
        return [f"{_display(path)} does not exist"]
    text = path.read_text(encoding="utf-8")
    lines = [line.rstrip() for line in text.splitlines()]
    failures: list[str] = []

    # Compared on whitespace-normalised text: the sentence is wrapped across lines in the
    # supplied record, and a student rewrapping the paragraph must not count as removing it.
    if INHERITED_SQS_STATEMENT not in " ".join(text.split()):
        failures.append(
            "Task 3.3's SQS limits statement was removed; the ECS section extends the record, it "
            "does not replace it"
        )

    heading_positions = [index for index, line in enumerate(lines) if line == REQUIRED_HEADING]
    if not heading_positions:
        failures.append(f"required heading is missing: {REQUIRED_HEADING!r}")
        return failures
    if len(heading_positions) > 1:
        failures.append(f"required heading appears more than once: {REQUIRED_HEADING!r}")
        return failures

    start = heading_positions[0]
    end = _next_heading_index(lines, start)
    section = lines[start + 1 : end]
    for code in REQUIRED_CODES:
        pattern = _code_pattern(code)
        if not any(pattern.match(line) for line in section):
            failures.append(
                f"required limitation code is missing from the ECS section, or is not on a line "
                f"of the form `- {code}: ...`: {code}"
            )
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
        print("Fidelity record findings:", file=sys.stderr)
        for problem in problems:
            print(f"- {problem}", file=sys.stderr)
        sys.exit(1)
    print(
        "Fidelity record verification passed: the ECS section and every required code are present."
    )
