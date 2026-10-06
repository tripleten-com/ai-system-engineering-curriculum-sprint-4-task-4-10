"""Coldline.

===================

File:              tests/unit/security/test_pii.py
Component:         Unit tests — Marked PII values and the four-location search
Purpose:           Prove the fixture loads with its marked values, the search finds a marked value
                    in the locations it is in and nowhere else, and the report prints no verdict.
Interacts With:    tests/security/pii.py, tests/fixtures/pii/notes.yaml, docs/security/redactor.md
Sprint/Task:       Sprint 4 — Project 4 / Task 4.4
Concepts:          Marked values as the unit of evidence, one rule for both scans
Tools:             Python 3.12, pytest

The search is exercised over synthetic location texts, never over a run of the worker.
Which supplied note the redactor handles wrongly is the student's finding, so nothing here
compares a supplied note's redaction with its marked values.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from adapters.model.deterministic import PII_ECHO_CONTACT, RESPONSES
from common.redactor import KINDS
from tests.security import pii

TASK_ROOT = Path(__file__).resolve().parents[3]


def test_the_fixture_holds_n01_and_at_least_five_more_notes_with_known_kinds() -> None:
    """Every note has an id, text, and marked values of a known kind that its text holds."""
    notes = pii.load_notes(TASK_ROOT)

    assert pii.FIRST_NOTE in notes
    assert len(notes) >= 6
    assert pii.note_ids(TASK_ROOT) == tuple(notes)
    for note in notes.values():
        assert note.text.strip()
        for item in note.marked:
            assert item.kind in KINDS
            assert item.value in note.text
            assert item.label == f"{note.note_id} {item.kind}"
    first = notes[pii.FIRST_NOTE]
    assert {item.kind for item in first.marked} == {"phone", "email"}
    assert any(not note.marked for note in notes.values()), "a note with no PII lists none"


def test_the_fixture_uses_reserved_domains_and_fictional_numbers_only() -> None:
    """Every email is at example.com or example.org and every phone is a 555-01xx number."""
    for note in pii.load_notes(TASK_ROOT).values():
        for item in note.marked:
            if item.kind == "email":
                assert item.value.endswith(("@example.com", "@example.org")), item.value
            if item.kind == "phone":
                assert "555" in item.value and "01" in item.value.rsplit("555", 1)[1], item.value


def test_a_malformed_fixture_is_refused_with_its_fault_named(tmp_path: Path) -> None:
    """A missing list, a bad id, a value the text lacks, an unknown kind: each is an error."""
    path = tmp_path / pii.NOTES_PATH
    path.parent.mkdir(parents=True)

    def write(text: str) -> None:
        path.write_text(text, encoding="utf-8")

    write("notes: []\n")
    with pytest.raises(ValueError, match="non-empty"):
        pii.load_notes(tmp_path)
    write("notes:\n  - id: N1\n    text: x\n    pii: []\n")
    with pytest.raises(ValueError, match="N-nn"):
        pii.load_notes(tmp_path)
    write(
        "notes:\n  - id: N-01\n    text: call the desk\n    pii:\n"
        "      - {kind: phone, value: '555-0100'}\n"
    )
    with pytest.raises(ValueError, match="does not hold"):
        pii.load_notes(tmp_path)
    write(
        "notes:\n  - id: N-01\n    text: 42 Relay Road\n    pii:\n"
        "      - {kind: address, value: '42 Relay Road'}\n"
    )
    with pytest.raises(ValueError, match="known kind"):
        pii.load_notes(tmp_path)
    write("notes:\n  - id: N-02\n    text: fine\n    pii: []\n")
    with pytest.raises(ValueError, match="must hold N-01"):
        pii.load_notes(tmp_path)
    write(
        "notes:\n  - id: N-01\n    text: fine\n    pii: []\n"
        "  - id: N-01\n    text: twice\n    pii: []\n"
    )
    with pytest.raises(ValueError, match="twice"):
        pii.load_notes(tmp_path)


def test_a_note_is_found_by_its_exact_text_and_by_its_id() -> None:
    """`note_for_text` matches the fixture's text exactly; `note_text` names unknown ids."""
    notes = pii.load_notes(TASK_ROOT)
    first = notes[pii.FIRST_NOTE]

    assert pii.note_for_text(first.text, notes) is first
    assert pii.note_for_text(first.text + " ", notes) is None
    assert pii.note_for_text("Re-ice at the Dover relay.", notes) is None
    assert pii.note_for_text(None, notes) is None
    assert pii.note_text(pii.FIRST_NOTE, TASK_ROOT) == first.text
    with pytest.raises(ValueError, match="unknown note"):
        pii.note_text("N-99", TASK_ROOT)


def test_marked_values_combine_a_note_and_a_response_and_refuse_unknown_names() -> None:
    """The note's values come first, then the response's; the other responses add nothing."""
    notes = pii.load_notes(TASK_ROOT)

    combined = pii.marked_values(notes, note=pii.FIRST_NOTE, response="pii-echo")
    assert [item.value for item in combined] == [
        *notes[pii.FIRST_NOTE].values,
        PII_ECHO_CONTACT,
    ]
    assert combined[-1].label == "pii-echo contact" and combined[-1].kind == "phone"
    for response in RESPONSES:
        if response != "pii-echo":
            assert pii.response_values(response) == ()
    assert pii.response_values(None) == ()
    assert pii.marked_values(notes) == ()
    with pytest.raises(ValueError, match="unknown note"):
        pii.marked_values(notes, note="N-99")
    with pytest.raises(ValueError, match="unknown response"):
        pii.marked_values(notes, response="surprise")


def test_the_search_names_each_value_in_each_location_it_is_in_and_nothing_else() -> None:
    """A value is a finding per location that holds it; an unread location is nothing."""
    values = (
        pii.MarkedValue("N-00 phone", "phone", "555-0100"),
        pii.MarkedValue("N-00 email", "email", "probe@example.com"),
    )
    locations = {
        "worker logs": "reading job handling_note=call 555-0100 or probe@example.com",
        "model request": '{"handling_note": "call [REDACTED:phone] or probe@example.com"}',
        "audit records": '{"state": "COMPLETED", "summary": "clean"}',
        "stored summary": "clean",
    }

    found = pii.findings(locations, values)

    assert pii.render(found) == [
        "worker logs: N-00 phone",
        "worker logs: N-00 email",
        "model request: N-00 email",
    ]
    # The rendering names the label and the location; the value found is never repeated.
    assert [item.value for item in found] == ["555-0100", "probe@example.com", "probe@example.com"]
    for line in pii.render(found):
        assert "555-0100" not in line and "probe@example.com" not in line
    assert pii.findings({"stored summary": "clean"}, values) == []
    assert pii.findings({}, values) == []
    assert pii.findings(locations, ()) == []


def test_details_text_renders_one_json_line_per_record() -> None:
    """The audit location is every record's details, rendered whole, one per line."""
    text = pii.details_text([{"state": "COMPLETED", "summary": "s"}, {"reason_code": "not_json"}])

    assert text.splitlines() == [
        '{"state": "COMPLETED", "summary": "s"}',
        '{"reason_code": "not_json"}',
    ]


def test_the_limitation_ids_are_read_from_the_documentation_table_in_order() -> None:
    """The ids are the first column of the limitations table, at least four of them."""
    ids = pii.limitation_ids(TASK_ROOT)

    assert len(ids) >= 4
    assert ids[0] == "RL-01"
    assert ids == tuple(f"RL-{index:02d}" for index in range(1, len(ids) + 1))
    assert len(set(ids)) == len(ids)


def test_the_report_prints_every_note_with_its_redaction_and_marked_values_and_no_verdict() -> None:
    """Three lines per note, the ids in fixture order, and no word that judges a note."""
    notes = pii.load_notes(TASK_ROOT)

    lines = pii.report_lines(notes)

    headings = [line for line in lines if line.startswith("## ")]
    assert headings == [f"## {note_id}" for note_id in notes]
    assert sum(line.startswith("original: ") for line in lines) == len(notes)
    assert sum(line.startswith("redacted: ") for line in lines) == len(notes)
    assert sum(line.startswith("marked:   ") for line in lines) == len(notes)
    for note in notes.values():
        assert f"original: {note.text}" in lines
    text = "\n".join(lines).lower()
    verdicts = ("mishandled", "wrong", "limitation", "false_negative", "false_positive", "rl-")
    for verdict in verdicts:
        assert verdict not in text, verdict
