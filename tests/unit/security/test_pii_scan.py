"""Coldline.

===================

File:              tests/unit/security/test_pii_scan.py
Component:         Unit tests — PII scan over the running stack
Purpose:           Prove `poe pii-scan` reads the four locations through the Compose commands,
                    resolves the run's marked values from the stored note and response, prints
                    what it found where by label and never the value, reports evidence that is
                    not there as unavailable (never clean), and exits by what it found, without
                    a stack.
Interacts With:    tests/security/pii_scan.py, tests/security/pii.py, tests/security/live_record.py,
                    tests/security/trail.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.4
Concepts:          Evidence per trust boundary, a search bounded to marked values
Tools:             Python 3.12, pytest

Every Compose call is replaced by a fake `subprocess.run` that answers from scripted
texts; no container is touched. The scripted texts are synthetic: a run of N-01 with its
values everywhere, the same run clean, the shipped scenario note, and a pii-echo run.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from adapters.model.deterministic import PII_ECHO_CONTACT
from tests.security import pii, pii_scan

TASK_ROOT = Path(__file__).resolve().parents[3]
EXCEPTION = "exc-0123abcd"
BASELINE_NOTE = "Re-ice at the Dover relay before the pallet moves."


class _Stack:
    """Script what each Compose command prints: the row, the logs, the request, the trail."""

    def __init__(
        self,
        *,
        row: dict[str, Any] | None,
        logs: str,
        request: str | None,
        details: list[dict[str, Any]],
        psql_failure: bool = False,
    ) -> None:
        self.row = row
        self.logs = logs
        self.request = request
        self.details = details
        self.psql_failure = psql_failure
        self.commands: list[list[str]] = []

    def __call__(self, command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        """Answer one command by what it asks for."""
        self.commands.append(command)
        if "psql" in command:
            if self.psql_failure:
                return subprocess.CompletedProcess(command, 1, "", "no such service")
            out = "" if self.row is None else json.dumps(self.row) + "\n"
            return subprocess.CompletedProcess(command, 0, out, "")
        if "logs" in command:
            return subprocess.CompletedProcess(command, 0, self.logs, "")
        if "worker.model_request" in command:
            if self.request is None:
                return subprocess.CompletedProcess(command, 1, "", "no model request recorded")
            return subprocess.CompletedProcess(command, 0, self.request, "")
        if "api.audit_trail" in command:
            lines = [
                json.dumps({"audit_id": index, "event": "e", "details": item})
                for index, item in enumerate(self.details, start=1)
            ]
            return subprocess.CompletedProcess(command, 0, "\n".join(lines) + "\n", "")
        raise AssertionError(f"unexpected command {command}")


def _row(note: str | None, response: str | None, summary: str) -> dict[str, Any]:
    return {
        "state": "COMPLETED",
        "summary": summary,
        "handling_note": note,
        "emulator_response": response,
    }


def _run(monkeypatch: pytest.MonkeyPatch, stack: _Stack) -> int:
    monkeypatch.setattr(subprocess, "run", stack)
    return pii_scan.main([EXCEPTION, "--root", str(TASK_ROOT)])


def test_a_run_that_leaks_n01_everywhere_is_reported_per_location_and_exits_one(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Both marked values of N-01 are named in each of the four locations."""
    note = pii.load_notes(TASK_ROOT)[pii.FIRST_NOTE]
    stack = _Stack(
        row=_row(note.text, "valid", f"Summary. Handling note: {note.text}"),
        logs=f"worker-1  | reading job exception_id={EXCEPTION} handling_note={note.text}\n"
        "worker-1  | reading job exception_id=exc-other handling_note=unrelated\n",
        request=json.dumps({"exception_id": EXCEPTION, "handling_note": note.text}),
        details=[{"reading_id": "r"}, {"state": "COMPLETED", "summary": note.text}],
    )

    assert _run(monkeypatch, stack) == 1

    out = capsys.readouterr().out
    assert f"pii-scan: exception {EXCEPTION}" in out
    assert "handling note: N-01 (2 marked value(s))" in out
    assert "response: valid (0 marked value(s))" in out
    found = "found N-01 phone, N-01 email"
    for location in pii.LOCATIONS:
        assert f"  {location}: {found}" in out
    assert "pii-scan: 8 marked value(s) found in 4 location(s)" in out
    # The scan names what it found by label; the values themselves are printed nowhere.
    for value in note.values:
        assert value not in out, value
    assert any("worker.model_request" in command for command in stack.commands)
    assert any("api.audit_trail" in command for command in stack.commands)


def test_a_clean_run_reports_every_location_clean_and_exits_zero(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """With placeholders everywhere nothing is found and the exit is 0."""
    note = pii.load_notes(TASK_ROOT)[pii.FIRST_NOTE]
    redacted = "send the log to [REDACTED:email], or call [REDACTED:phone]"
    stack = _Stack(
        row=_row(note.text, "valid", f"Summary. Handling note: {redacted}"),
        logs=f"worker-1  | reading job exception_id={EXCEPTION} handling_note={redacted}\n",
        request=json.dumps({"exception_id": EXCEPTION, "handling_note": redacted}),
        details=[{"state": "COMPLETED", "summary": redacted}],
    )

    assert _run(monkeypatch, stack) == 0

    out = capsys.readouterr().out
    for location in pii.LOCATIONS:
        assert f"  {location}: clean" in out
    assert "pii-scan: no marked value found in any location" in out


def test_the_shipped_scenario_note_has_no_marked_values_and_the_scan_says_so(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A note outside the fixture is not scanned for note values; with `valid` nothing is."""
    stack = _Stack(
        row=_row(BASELINE_NOTE, None, "Summary."),
        logs=f"worker-1  | reading job exception_id={EXCEPTION}\n",
        request="{}",
        details=[],
    )

    assert _run(monkeypatch, stack) == 0

    out = capsys.readouterr().out
    assert "handling note: not a supplied fixture note" in out
    assert "response: valid (0 marked value(s))" in out
    assert "pii-scan: no marked values to search for" in out


def test_the_pii_echo_contact_is_found_in_the_summary_and_the_trail_only(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The response's marked value is searched even when the note is the shipped one."""
    stack = _Stack(
        row=_row(BASELINE_NOTE, "pii-echo", f"Summary. reach the desk on {PII_ECHO_CONTACT}."),
        logs=f"worker-1  | reading job exception_id={EXCEPTION}\n",
        request=json.dumps({"exception_id": EXCEPTION, "handling_note": BASELINE_NOTE}),
        details=[{"state": "COMPLETED", "summary": f"on {PII_ECHO_CONTACT}."}],
    )

    assert _run(monkeypatch, stack) == 1

    out = capsys.readouterr().out
    assert "response: pii-echo (1 marked value(s))" in out
    assert "  worker logs: clean" in out
    assert "  model request: clean" in out
    assert "  audit records: found pii-echo contact\n" in out
    assert "  stored summary: found pii-echo contact\n" in out
    assert "pii-scan: 2 marked value(s) found in 2 location(s)" in out
    assert PII_ECHO_CONTACT not in out


def test_a_missing_request_record_is_unavailable_never_clean_and_the_scan_exits_two(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A finished run whose request record is gone: the other three are clean, the exit is 2.

    The worker container was recreated since the run, say: the record kept its clean
    summary and audit rows, but the request record is gone. The scan says so for that
    location and refuses to call the run clean.
    """
    note = pii.load_notes(TASK_ROOT)[pii.FIRST_NOTE]
    redacted = "send the log to [REDACTED:email], or call [REDACTED:phone]"
    stack = _Stack(
        row=_row(note.text, "valid", f"Summary. Handling note: {redacted}"),
        logs=f"worker-1  | reading job exception_id={EXCEPTION} handling_note={redacted}\n",
        request=None,
        details=[{"state": "COMPLETED", "summary": redacted}],
    )

    assert _run(monkeypatch, stack) == 2

    out = capsys.readouterr().out
    assert "  model request: unavailable (no request record for this exception" in out
    assert "  model request: clean" not in out
    for location in ("worker logs", "audit records", "stored summary"):
        assert f"  {location}: clean" in out
    assert "pii-scan: no marked value found in the searched locations" in out
    assert "pii-scan: incomplete; 1 location(s) unavailable (model request)" in out
    assert "no marked value found in any location" not in out


def test_worker_logs_with_no_line_naming_the_exception_are_unavailable(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Logs that name other exceptions only are not this run's clean logs; the exit is 2."""
    note = pii.load_notes(TASK_ROOT)[pii.FIRST_NOTE]
    redacted = "send the log to [REDACTED:email], or call [REDACTED:phone]"
    stack = _Stack(
        row=_row(note.text, "valid", f"Summary. Handling note: {redacted}"),
        logs="worker-1  | reading job exception_id=exc-other handling_note=unrelated\n",
        request=json.dumps({"exception_id": EXCEPTION, "handling_note": redacted}),
        details=[{"state": "COMPLETED", "summary": redacted}],
    )

    assert _run(monkeypatch, stack) == 2

    out = capsys.readouterr().out
    assert "  worker logs: unavailable (no worker log line names this exception" in out
    assert "  worker logs: clean" not in out
    assert "  model request: clean" in out
    assert "pii-scan: incomplete; 1 location(s) unavailable (worker logs)" in out


def test_a_finding_beside_an_unavailable_location_is_printed_and_the_scan_exits_two(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """What was found in the readable locations is still named; the scan is incomplete."""
    note = pii.load_notes(TASK_ROOT)[pii.FIRST_NOTE]
    stack = _Stack(
        row=_row(note.text, "valid", "clean"),
        logs=f"worker-1  | reading job exception_id={EXCEPTION} handling_note={note.text}\n",
        request=None,
        details=[],
    )

    assert _run(monkeypatch, stack) == 2

    out = capsys.readouterr().out
    assert "  worker logs: found N-01 phone, N-01 email\n" in out
    for value in note.values:
        assert value not in out, value
    assert "  model request: unavailable" in out
    assert "pii-scan: 2 marked value(s) found in 1 location(s)" in out
    assert "pii-scan: incomplete; 1 location(s) unavailable (model request)" in out


def test_live_locations_report_missing_evidence_as_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """The function the assessed rows share with the CLI returns None for a missing location."""
    note = pii.load_notes(TASK_ROOT)[pii.FIRST_NOTE]
    stack = _Stack(
        row=_row(note.text, "valid", "Summary."),
        logs="worker-1  | reading job exception_id=exc-other\n",
        request=None,
        details=[{"state": "COMPLETED", "summary": "Summary."}],
    )
    monkeypatch.setattr(subprocess, "run", stack)

    locations = pii_scan.live_locations(EXCEPTION, TASK_ROOT)

    assert locations["worker logs"] is None and locations["model request"] is None
    assert locations["stored summary"] == "Summary."
    assert pii_scan.unavailable_locations(locations) == ["worker logs", "model request"]
    assert pii.findings(locations, note.marked) == []


def test_a_database_failure_or_an_unknown_exception_is_a_tooling_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A failing poll or a missing row exits 2 with the reason, never a clean verdict."""
    failing = _Stack(row=None, logs="", request=None, details=[], psql_failure=True)
    assert _run(monkeypatch, failing) == 2
    assert "pii-scan: the database poll failed" in capsys.readouterr().err

    absent = _Stack(row=None, logs="", request=None, details=[])
    assert _run(monkeypatch, absent) == 2
    assert f"exception {EXCEPTION} is not in the database" in capsys.readouterr().err


def test_applicable_values_resolve_the_note_by_text_and_the_response_by_name() -> None:
    """The stored note's exact text picks the fixture note; the response picks its values."""
    notes = pii.load_notes(TASK_ROOT)
    note, response, values = pii_scan.applicable_values(
        _row(notes[pii.FIRST_NOTE].text, "pii-echo", ""), notes
    )
    assert note is notes[pii.FIRST_NOTE] and response == "pii-echo"
    assert [item.value for item in values] == [*notes[pii.FIRST_NOTE].values, PII_ECHO_CONTACT]

    note, response, values = pii_scan.applicable_values(_row(BASELINE_NOTE, None, ""), notes)
    assert note is None and response is None and values == ()
