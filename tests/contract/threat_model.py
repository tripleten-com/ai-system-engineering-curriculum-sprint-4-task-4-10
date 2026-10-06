"""Coldline.

===================

File:              tests/contract/threat_model.py
Component:         Contract tests — Threat model structure
Purpose:           Check docs/student/threat-model.md for its four sections and their entries.
Interacts With:    docs/student/threat-model.md, docs/security/*, submission.yaml
Sprint/Task:       Sprint 4 — Project 4
Concepts:          Threat model, deterministic assessment, structure not prose
Tools:             Python 3.12, PyYAML

This module is a ``findings()``-style checker in the same spirit as
``tests/contract/runbook_contract.py``. It reads one student-written Markdown
file and reports every structural reason it is not yet a complete threat model:

- the file does not exist, or a required level-two heading is missing, repeated, or
  out of order;
- a template marker is still in place;
- the first section names no trace id (32 hexadecimal digits);
- the second section has no line of its own for one of the catalog's threat ids
  (a line naming several ids is a line for none of them);
- the third section has no entry of its own for one of the ids in
  ``answers.top_threats`` (the same rule: one entry names one id);
- the last section has no content of its own.

It grades nothing about the prose. Which flows cross a boundary, why a
likelihood is what it is, and whether an abuse case is concrete are for the
Task 4 Instructor Review; this check only guarantees the entries are there.

The supplied security material is read here too, so the public answer-format
check and these structural checks agree on one set of ids: the flows come from
``docs/security/workflow.md``, the threats from ``docs/security/threat-catalog.yaml``,
and the controls from ``docs/security/control-matrix.md``.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

TASK_ROOT = Path(__file__).resolve().parents[2]
THREAT_MODEL_PATH = TASK_ROOT / "docs/student/threat-model.md"
WORKFLOW_PATH = TASK_ROOT / "docs/security/workflow.md"
CATALOG_PATH = TASK_ROOT / "docs/security/threat-catalog.yaml"
CONTROL_MATRIX_PATH = TASK_ROOT / "docs/security/control-matrix.md"
# Exact, case-sensitive, whole-line headings, in this order. Documented verbatim in
# docs/student/task-4-1-contract.md; a change here is a contract change.
REQUIRED_HEADINGS = (
    "## 1. Boundaries and the trace",
    "## 2. Likelihood basis",
    "## 3. Abuse cases",
    "## 4. What this model leaves out",
)
# Every fillable spot in the supplied template carries one of these. The first is the
# prose placeholder every earlier Task's student docs use; the other two stand where
# the student writes a flow id or a threat id.
TEMPLATE_MARKERS = ("_Write your evidence here._", "DF-xx", "TH-xx")
STRIDE_CATEGORIES = (
    "spoofing",
    "tampering",
    "repudiation",
    "information_disclosure",
    "denial_of_service",
    "elevation_of_privilege",
)
LIKELIHOOD_SCALE = ("low", "medium", "high")
_TRACE_ID = re.compile(r"\b[0-9a-f]{32}\b")
_FLOW_ROW = re.compile(r"^\|\s*(DF-\d{2})\s*\|", re.MULTILINE)
_CONTROL_ROW = re.compile(r"^\|\s*(C-\d{2})\s*\|", re.MULTILINE)
_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_THREAT_ID = re.compile(r"\bTH-\d{2}\b")


def flow_ids(path: Path = WORKFLOW_PATH) -> tuple[str, ...]:
    """Return the numbered data-flow ids the workflow description tables."""
    return tuple(dict.fromkeys(_FLOW_ROW.findall(path.read_text(encoding="utf-8"))))


def threat_ids(path: Path = CATALOG_PATH) -> tuple[str, ...]:
    """Return the catalog's threat ids in catalog order."""
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    threats = document.get("threats") if isinstance(document, dict) else None
    if not isinstance(threats, list):
        raise ValueError(f"{_display(path)} declares no threats list")
    identifiers: list[str] = []
    for entry in threats:
        identifier = entry.get("id") if isinstance(entry, dict) else None
        if not isinstance(identifier, str):
            raise ValueError(f"{_display(path)} holds a threat without an id")
        identifiers.append(identifier)
    return tuple(identifiers)


def control_ids(path: Path = CONTROL_MATRIX_PATH) -> tuple[str, ...]:
    """Return the control ids the control matrix tables."""
    return tuple(dict.fromkeys(_CONTROL_ROW.findall(path.read_text(encoding="utf-8"))))


def remaining_markers(text: str) -> list[str]:
    """Return every template marker still present, in a stable order."""
    visible = _COMMENT.sub("", text)
    return [marker for marker in TEMPLATE_MARKERS if marker in visible]


def findings(
    path: Path = THREAT_MODEL_PATH,
    *,
    catalog: tuple[str, ...] | None = None,
    top_threats: tuple[str, ...] = (),
) -> list[str]:
    """Return every structural reason the threat model is incomplete, or an empty list.

    ``catalog`` defaults to the supplied catalog's ids; ``top_threats`` is the
    student's own ranked list, read from the answer sheet by the caller, so a
    sheet that names no top threats makes the third section unchecked rather
    than failing on an absent list.
    """
    if not path.is_file():
        return [f"{_display(path)} does not exist"]
    text = _COMMENT.sub("", path.read_text(encoding="utf-8"))
    failures = [f"template marker still present: {marker!r}" for marker in remaining_markers(text)]
    sections = _sections(text)
    if isinstance(sections, list):
        return failures + sections

    first, second, third, last = tuple(sections[heading] for heading in REQUIRED_HEADINGS)
    if _TRACE_ID.search(first) is None:
        failures.append(f"{REQUIRED_HEADINGS[0]!r} names no trace id (32 hexadecimal digits)")
    for identifier in catalog if catalog is not None else threat_ids():
        if not _has_entry(second, identifier):
            failures.append(f"{REQUIRED_HEADINGS[1]!r} has no line of its own for {identifier}")
    for identifier in top_threats:
        if not _has_entry(third, identifier):
            failures.append(f"{REQUIRED_HEADINGS[2]!r} has no abuse case for {identifier}")
    if not _present_lines(last):
        failures.append(f"{REQUIRED_HEADINGS[3]!r} has no content of its own")
    return failures


def _sections(text: str) -> dict[str, str] | list[str]:
    """Split the document into its four required sections, or explain why it cannot."""
    lines = [line.rstrip() for line in text.splitlines()]
    positions: dict[str, list[int]] = {heading: [] for heading in REQUIRED_HEADINGS}
    for index, line in enumerate(lines):
        if line in positions:
            positions[line].append(index)
    failures: list[str] = []
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
        return ["required headings are out of order; expected " + ", ".join(REQUIRED_HEADINGS)]
    sections: dict[str, str] = {}
    for heading, start in zip(REQUIRED_HEADINGS, ordered, strict=True):
        end = _next_section_index(lines, start)
        sections[heading] = "\n".join(lines[start + 1 : end])
    return sections


def _next_section_index(lines: list[str], start: int) -> int:
    """Return the index of the next level-one or level-two heading after ``start``."""
    for index in range(start + 1, len(lines)):
        if lines[index].startswith(("# ", "## ")):
            return index
    return len(lines)


def _present_lines(section: str) -> list[str]:
    """Return the lines of a section that are neither blank nor a heading.

    A template marker counts as a present line here: the marker check reports
    it on its own, so one leftover placeholder is one finding, not two.
    """
    return [
        line for line in section.splitlines() if line.strip() and not line.strip().startswith("#")
    ]


def _has_entry(section: str, identifier: str) -> bool:
    """Return whether a section has an entry of its own for one id.

    An entry starts on a line that names exactly one threat id, this one: a
    line naming several ids ("TH-01, TH-02: ...", or a heading listing them) is
    an entry for none of them, so one shared line cannot stand for every
    threat. That line is the entry when it carries words beyond the id and a
    rank label; otherwise the entry is the first line after it, before the
    next heading or the next line naming a threat id, that is neither blank
    nor a heading.
    """
    lines = section.splitlines()
    for index, line in enumerate(lines):
        if _THREAT_ID.findall(line) != [identifier]:
            continue
        own = line.replace(identifier, "")
        if _present_lines(own) and _words(own):
            return True
        for following in lines[index + 1 :]:
            if following.strip().startswith("#") or _THREAT_ID.search(following):
                break
            if _present_lines(following):
                return True
    return False


def _words(text: str) -> bool:
    """Return whether a line carries words beyond a rank label and punctuation."""
    cleaned = re.sub(r"(?i)\brank\s*\d+\b", "", text)
    return bool(re.search(r"[A-Za-z]{2,}", cleaned))


def _display(path: Path) -> str:
    """Name a path relative to the Task root when it lives there, else as given."""
    try:
        return path.relative_to(TASK_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


if __name__ == "__main__":
    problems = findings()
    if problems:
        print("Threat model findings:", file=sys.stderr)
        for problem in problems:
            print(f"- {problem}", file=sys.stderr)
        sys.exit(1)
    print("Threat model verification passed: every section carries the entries it needs.")
