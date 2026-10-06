"""Coldline.

===================

File:              tests/security/pii.py
Component:         Security tooling — Marked PII values and the four-location search
Purpose:           Load the supplied notes with their marked values, know the marked values of
                    the supplied responses, and search a run's four locations for them.
Interacts With:    tests/fixtures/pii/notes.yaml, docs/security/redactor.md,
                    src/common/redactor.py, src/adapters/model/deterministic.py,
                    tests/security/pii_scan.py, tests/security/redaction_report.py,
                    tests/security/interaction.py, tests/contract/test_redaction_contract.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.4
Concepts:          Marked values as the unit of evidence, one rule for the live and the
                    in-process scan, a report without a verdict
Tools:             Python 3.12, PyYAML

The rules here are stated once over plain strings, so ``poe pii-scan`` (which reads the
running stack) and ``InteractionHarness.pii_findings`` (which reads the in-process run)
search the same way: each marked value is looked for, as a substring, in each of the four
locations the lesson names, in this order:

- ``worker logs``: the worker's log lines about the exception;
- ``model request``: the text of the request the model emulator received;
- ``audit records``: every audit record's ``details``, rendered as JSON;
- ``stored summary``: the record's ``summary`` column.

A marked value is one the supplied fixture marks for a note (``tests/fixtures/pii/notes.yaml``,
``pii:`` per note) or one the emulator's supplied response adds (``RESPONSE_VALUES``: the
``pii-echo`` contact). The search knows nothing about personal data in general: a clean
scan says that these values are absent from these places, and nothing more. A finding is
rendered as its location and its label (``worker logs: N-01 phone``), never as the value:
the scan's output goes into terminal history and pull requests, and must not become one
more place the detail reaches. ``report_lines`` renders the redaction report: for every
note, the original text, the redacted text and the marked values; it prints the values on
purpose, because comparing them is the reader's work, and no verdict about any note.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

import yaml

from adapters.model.deterministic import PII_ECHO_CONTACT, RESPONSES
from common.redactor import KINDS, redact

TASK_ROOT = Path(__file__).resolve().parents[2]
NOTES_PATH = Path("tests/fixtures/pii/notes.yaml")
REDACTOR_DOCUMENT = Path("docs/security/redactor.md")
# The four places the scan searches, in the order it reports them.
LOCATIONS: tuple[str, ...] = ("worker logs", "model request", "audit records", "stored summary")
# The note the lesson's Step 1 runs first; the fixture must carry it.
FIRST_NOTE = "N-01"
_NOTE_ID = re.compile(r"^N-\d{2}$")
_LIMITATION_ROW = re.compile(r"^\| (RL-\d{2}) \|")


@dataclass(frozen=True)
class MarkedValue:
    """One value a fixture marks as personal detail: where it came from, its kind, the text."""

    label: str
    kind: str
    value: str


@dataclass(frozen=True)
class Note:
    """One supplied handling note with the values its fixture marks."""

    note_id: str
    text: str
    marked: tuple[MarkedValue, ...]

    @property
    def values(self) -> tuple[str, ...]:
        """Return the marked values' text, in fixture order."""
        return tuple(item.value for item in self.marked)


@dataclass(frozen=True)
class Finding:
    """One marked value found in one location.

    The value is kept for a caller that needs it; nothing rendered from a finding repeats
    it, so a scan's output and a failing row's message name the label and the location
    only and never copy the detail they found into another place.
    """

    location: str
    label: str
    value: str

    def rendered(self) -> str:
        """Return the finding as one line: the location and the label, never the value."""
        return f"{self.location}: {self.label}"


# The marked values of the supplied emulator responses: `pii-echo` adds one contact number
# that no supplied note or request carries. The other responses add nothing.
RESPONSE_VALUES: dict[str, tuple[MarkedValue, ...]] = {
    "pii-echo": (MarkedValue("pii-echo contact", "phone", PII_ECHO_CONTACT),),
}


def load_notes(root: Path = TASK_ROOT) -> dict[str, Note]:
    """Return the supplied notes by id, in fixture order, validating the fixture's shape."""
    path = root / NOTES_PATH
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    entries = document.get("notes") if isinstance(document, dict) else None
    if not isinstance(entries, list) or not entries:
        raise ValueError(f"{NOTES_PATH.as_posix()} must hold a non-empty `notes:` list")
    notes: dict[str, Note] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError(f"{NOTES_PATH.as_posix()}: every note is a mapping")
        note_id = entry.get("id")
        text = entry.get("text")
        marked = entry.get("pii")
        if not isinstance(note_id, str) or not _NOTE_ID.match(note_id):
            raise ValueError(
                f"{NOTES_PATH.as_posix()}: a note id has the form N-nn, not {note_id!r}"
            )
        if note_id in notes:
            raise ValueError(f"{NOTES_PATH.as_posix()}: note {note_id} appears twice")
        if not isinstance(text, str) or not text.strip():
            raise ValueError(f"{NOTES_PATH.as_posix()}: note {note_id} has no text")
        if not isinstance(marked, list):
            raise ValueError(f"{NOTES_PATH.as_posix()}: note {note_id} lists no `pii:` list")
        values: list[MarkedValue] = []
        for item in marked:
            kind = item.get("kind") if isinstance(item, dict) else None
            value = item.get("value") if isinstance(item, dict) else None
            if kind not in KINDS or not isinstance(value, str) or not value:
                raise ValueError(
                    f"{NOTES_PATH.as_posix()}: note {note_id} marks a value without a known "
                    f"kind ({', '.join(KINDS)}) and a non-empty text"
                )
            if value not in text:
                raise ValueError(
                    f"{NOTES_PATH.as_posix()}: note {note_id} marks a value its text does not hold"
                )
            values.append(MarkedValue(f"{note_id} {kind}", kind, value))
        notes[note_id] = Note(note_id, text, tuple(values))
    if FIRST_NOTE not in notes:
        raise ValueError(f"{NOTES_PATH.as_posix()} must hold {FIRST_NOTE}")
    return notes


def note_ids(root: Path = TASK_ROOT) -> tuple[str, ...]:
    """Return the supplied note ids, in fixture order."""
    return tuple(load_notes(root))


def note_text(note_id: str, root: Path = TASK_ROOT) -> str:
    """Return one supplied note's text, or raise naming the ids that exist."""
    notes = load_notes(root)
    if note_id not in notes:
        raise ValueError(f"unknown note {note_id!r}; choose one of {', '.join(notes)}")
    return notes[note_id].text


def note_for_text(text: str | None, notes: Mapping[str, Note]) -> Note | None:
    """Return the supplied note whose text is exactly ``text``, or None for any other note."""
    if text is None:
        return None
    for note in notes.values():
        if note.text == text:
            return note
    return None


def response_values(response: str | None) -> tuple[MarkedValue, ...]:
    """Return the marked values a supplied response adds; none for an unknown or absent one."""
    if response is None:
        return ()
    return RESPONSE_VALUES.get(response, ())


def marked_values(
    notes: Mapping[str, Note], *, note: str | None = None, response: str | None = None
) -> tuple[MarkedValue, ...]:
    """Return the marked values of one note and one response, the note's first.

    ``note`` is a supplied note id (``N-01``); ``response`` a supplied response name. A name
    outside the fixture is an error, not an empty answer, so a misspelt id cannot make a
    scan pass.
    """
    values: list[MarkedValue] = []
    if note is not None:
        if note not in notes:
            raise ValueError(f"unknown note {note!r}; choose one of {', '.join(notes)}")
        values.extend(notes[note].marked)
    if response is not None:
        if response not in RESPONSES:
            choices = ", ".join(RESPONSES)
            raise ValueError(f"unknown response {response!r}; choose one of {choices}")
        values.extend(response_values(response))
    return tuple(values)


def limitation_ids(root: Path = TASK_ROOT) -> tuple[str, ...]:
    """Return the limitation ids the redactor's documentation lists, in table order."""
    document = (root / REDACTOR_DOCUMENT).read_text(encoding="utf-8")
    found: list[str] = []
    for line in document.splitlines():
        match = _LIMITATION_ROW.match(line)
        if match and match.group(1) not in found:
            found.append(match.group(1))
    if not found:
        raise ValueError(f"{REDACTOR_DOCUMENT.as_posix()} lists no limitation ids")
    return tuple(found)


def findings(
    locations: Mapping[str, str | None],
    values: Sequence[MarkedValue],
    *,
    order: Sequence[str] = LOCATIONS,
) -> list[Finding]:
    """Return every marked value found in every location, in location order then value order.

    ``locations`` maps a location name to its text; ``order`` names the locations to
    search and the order to report them in (the four live locations unless the caller
    searches others, as the in-process observation does with the captured streams). A
    location that is absent from the mapping, or mapped to None (``poe pii-scan`` could
    not read it), is reported as nothing, never as clean: the caller says it was
    unavailable.
    """
    found: list[Finding] = []
    for location in order:
        text = locations.get(location)
        if text is None:
            continue
        for item in values:
            if item.value in text:
                found.append(Finding(location, item.label, item.value))
    return found


def render(found: Iterable[Finding]) -> list[str]:
    """Return the findings as lines, one per finding."""
    return [finding.rendered() for finding in found]


def details_text(details: Iterable[Mapping[str, object]]) -> str:
    """Return audit records' details as text, one JSON line per record, for the search."""
    return "\n".join(json.dumps(dict(item), sort_keys=True, default=str) for item in details)


def report_lines(notes: Mapping[str, Note]) -> list[str]:
    """Return the redaction report: each note's id, original, redacted text and marked values.

    No verdict is printed about any note: comparing the redacted text with the marked
    values is the reader's work.
    """
    lines: list[str] = []
    for note in notes.values():
        marked = ", ".join(f"{item.kind}: {item.value}" for item in note.marked) or "none"
        lines.extend(
            [
                f"## {note.note_id}",
                f"original: {note.text}",
                f"redacted: {redact(note.text)}",
                f"marked:   {marked}",
                "",
            ]
        )
    return lines
