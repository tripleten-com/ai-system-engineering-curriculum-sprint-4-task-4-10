"""Coldline.

===================

File:              tests/security/policy.py
Component:         Security tooling — Access policy reader
Purpose:           Read the two machine-checked values of docs/security/access-policy.md.
Interacts With:    docs/security/access-policy.md, tests/security/auth_config.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.2
Concepts:          Policy as the source of configuration, structure not prose
Tools:             Python 3.12

The policy is prose for the student and two table rows for the checks: the API audience
row and the ``leeway_seconds`` range row. Both are read by their first cell, so the rest
of the document can be revised without touching this module.
"""

from __future__ import annotations

import re
from pathlib import Path

TASK_ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = TASK_ROOT / "docs/security/access-policy.md"
_AUDIENCE_ROW = re.compile(r"^\|\s*API audience[^|]*\|\s*`([^`]+)`\s*\|", re.MULTILINE)
_LEEWAY_ROW = re.compile(r"^\|\s*`leeway_seconds`\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|", re.MULTILINE)


def audience(path: Path = POLICY_PATH) -> str:
    """Return the API audience the policy names."""
    match = _AUDIENCE_ROW.search(path.read_text(encoding="utf-8"))
    if match is None:
        raise ValueError(f"{path.name} has no `API audience` row")
    return match.group(1)


def leeway_range(path: Path = POLICY_PATH) -> tuple[int, int]:
    """Return the inclusive ``leeway_seconds`` range the policy allows."""
    match = _LEEWAY_ROW.search(path.read_text(encoding="utf-8"))
    if match is None:
        raise ValueError(f"{path.name} has no `leeway_seconds` range row")
    low, high = int(match.group(1)), int(match.group(2))
    if low > high:
        raise ValueError(f"{path.name} states an empty leeway range {low}..{high}")
    return low, high
