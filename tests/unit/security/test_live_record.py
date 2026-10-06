"""Coldline.

===================

File:              tests/unit/security/test_live_record.py
Component:         Unit tests — Stored exception through the running stack
Purpose:           Prove the assessed rows' precondition waits through the database and raises
                    on FAILED or timeout, that a submission can carry a note and a trace of the
                    checks' choosing, and that the PII scan's record query reads the four
                    columns it needs, without Docker or a stack.
Interacts With:    tests/security/live_record.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.4
Concepts:          Assessment preconditions, authorization-independent evidence
Tools:             Python 3.12, pytest

The Compose call is replaced by a fake `subprocess.run` that returns scripted `psql` rows;
no container is touched. The notes sent here are synthetic phrases, not fixture notes.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest

from tests.security import live_record

BASELINE_NOTE = "Re-ice at the Dover relay before the pallet moves."
TRACE_ID = "ab" * 16


class _Psql:
    """Script the rows `psql -tA` would print, one per poll, and record the queries."""

    def __init__(self, rows: list[str | None], returncode: int = 0, stderr: str = "") -> None:
        self.rows = list(rows)
        self.returncode = returncode
        self.stderr = stderr
        self.commands: list[list[str]] = []

    def __call__(self, command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        self.commands.append(command)
        row = self.rows.pop(0) if self.rows else None
        return subprocess.CompletedProcess(
            command, self.returncode, "" if row is None else row + "\n", self.stderr
        )


@pytest.fixture
def no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make polling instantaneous."""
    monkeypatch.setattr(live_record.time, "sleep", lambda _: None)


@pytest.fixture
def baseline(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Point the module at a small baseline reading carrying the shipped scenario note."""
    path = tmp_path / "baseline-exception.json"
    path.write_text(
        json.dumps(
            {
                "scenario_id": "s",
                "reading": {
                    "reading_id": "r",
                    "shipment_id": "s",
                    "temperature_c": 9.2,
                    "allowed_min_c": 2.0,
                    "allowed_max_c": 8.0,
                    "recorded_at": "2026-01-01T00:00:00Z",
                    "handling_note": BASELINE_NOTE,
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(live_record, "BASELINE_PATH", path)
    return path


def test_the_wait_polls_the_database_until_completed_with_a_summary(
    monkeypatch: pytest.MonkeyPatch, no_sleep: None
) -> None:
    """Absent, then queued, then completed-without-summary rows keep polling; the last returns."""
    psql = _Psql([None, "QUEUED|0", "COMPLETED|0", "COMPLETED|212"])
    monkeypatch.setattr(live_record.subprocess, "run", psql)

    live_record.wait_for_stored_summary("exc-1234abcd", wait_seconds=30.0, root=Path("."))

    assert len(psql.commands) == 4
    command = psql.commands[0]
    assert command[: len(live_record.COMPOSE)] == list(live_record.COMPOSE)
    assert command[len(live_record.COMPOSE) :][:4] == ["exec", "-T", "postgres", "psql"]
    assert command[-1] == (
        "SELECT state, coalesce(length(summary), 0) FROM exceptions "
        "WHERE exception_id = 'exc-1234abcd';"
    )
    # The poll never sends a bearer token and never touches the summary route.
    assert not any("Authorization" in part or "/api/v1/" in part for part in command)


def test_failed_raises_at_once_and_a_timeout_raises_with_the_last_state_seen(
    monkeypatch: pytest.MonkeyPatch, no_sleep: None
) -> None:
    """FAILED is a fixture error immediately; a deadline is one naming what was last seen."""
    monkeypatch.setattr(live_record.subprocess, "run", _Psql(["PROCESSING|0", "FAILED|0"]))
    with pytest.raises(live_record.StoredRecordError, match="reached FAILED"):
        live_record.wait_for_stored_summary("exc-1", wait_seconds=30.0, root=Path("."))

    monkeypatch.setattr(live_record.subprocess, "run", _Psql(["PROCESSING|0"]))
    with pytest.raises(live_record.StoredRecordError, match="did not reach COMPLETED .*PROCESSING"):
        live_record.wait_for_stored_summary("exc-1", wait_seconds=0.0, root=Path("."))

    monkeypatch.setattr(live_record.subprocess, "run", _Psql([None]))
    with pytest.raises(live_record.StoredRecordError, match="not yet visible"):
        live_record.wait_for_stored_summary("exc-1", wait_seconds=0.0, root=Path("."))


def test_wait_for_finished_returns_whichever_finished_state_the_record_reached(
    monkeypatch: pytest.MonkeyPatch, no_sleep: None
) -> None:
    """COMPLETED, NEEDS_REVIEW and FAILED all end the wait; only a deadline is an error."""
    monkeypatch.setattr(
        live_record.subprocess, "run", _Psql([None, "PROCESSING|0", "NEEDS_REVIEW|40"])
    )
    state = live_record.wait_for_finished("exc-1", wait_seconds=30.0, root=Path("."))
    assert state == "NEEDS_REVIEW"

    monkeypatch.setattr(live_record.subprocess, "run", _Psql(["FAILED|0"]))
    assert live_record.wait_for_finished("exc-1", wait_seconds=30.0, root=Path(".")) == "FAILED"

    monkeypatch.setattr(live_record.subprocess, "run", _Psql(["QUEUED|0"]))
    with pytest.raises(live_record.StoredRecordError, match="did not finish .*QUEUED"):
        live_record.wait_for_finished("exc-1", wait_seconds=0.0, root=Path("."))


def test_a_poll_that_cannot_run_is_an_error_not_a_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    """A failing psql, a missing docker, and an unreadable row each raise with the reason."""
    monkeypatch.setattr(
        live_record.subprocess, "run", _Psql([""], returncode=1, stderr="no such service")
    )
    with pytest.raises(live_record.StoredRecordError, match="exit 1.*no such service"):
        live_record.stored_state("exc-1", Path("."))

    def missing(*_: Any, **__: Any) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError("docker")

    monkeypatch.setattr(live_record.subprocess, "run", missing)
    with pytest.raises(live_record.StoredRecordError, match="could not run"):
        live_record.stored_state("exc-1", Path("."))

    monkeypatch.setattr(live_record.subprocess, "run", _Psql(["COMPLETED|many"]))
    with pytest.raises(live_record.StoredRecordError, match="unreadable database row"):
        live_record.stored_state("exc-1", Path("."))


def test_only_api_shaped_identities_reach_the_query(monkeypatch: pytest.MonkeyPatch) -> None:
    """An id with a quote, a space, or nothing in it is refused before any subprocess runs."""
    psql = _Psql([])
    monkeypatch.setattr(live_record.subprocess, "run", psql)
    for bad in ("exc-1' OR '1'='1", "exc 1", "", "x" * 121):
        with pytest.raises(live_record.StoredRecordError, match="unexpected exception id"):
            live_record.stored_state(bad, Path("."))
        with pytest.raises(live_record.StoredRecordError, match="unexpected exception id"):
            live_record.stored_scan_record(bad, Path("."))
    assert psql.commands == []


def test_stored_record_and_the_scan_record_read_their_columns_as_one_json_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each query selects its columns through `row_to_json`; the scan reads the stored reading."""
    scan_row = {
        "state": "COMPLETED",
        "summary": "Summary. Handling note: hold at the relay.",
        "handling_note": "hold at the relay",
        "emulator_response": "pii-echo",
    }
    psql = _Psql([json.dumps(scan_row)])
    monkeypatch.setattr(live_record.subprocess, "run", psql)

    assert live_record.stored_scan_record("exc-1", Path(".")) == scan_row

    sql = psql.commands[0][-1]
    assert sql.startswith("SELECT row_to_json(t) FROM (SELECT ")
    assert sql.endswith("FROM exceptions WHERE exception_id = 'exc-1') t;")
    for column in live_record.SCAN_COLUMNS:
        assert column in sql
    assert "reading->>'emulator_response' AS emulator_response" in sql
    assert "handling_note" in sql

    record_row = dict.fromkeys(live_record.RECORD_COLUMNS)
    record_row["state"] = "NEEDS_REVIEW"
    psql = _Psql([json.dumps(record_row)])
    monkeypatch.setattr(live_record.subprocess, "run", psql)
    assert live_record.stored_record("exc-1", Path(".")) == record_row
    assert ", ".join(live_record.RECORD_COLUMNS) in psql.commands[0][-1]
    assert "handling_note" not in psql.commands[0][-1]


def test_an_absent_or_unreadable_json_row_is_none_or_an_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No row is None (the record is not there); a row that is not a JSON object is an error."""
    monkeypatch.setattr(live_record.subprocess, "run", _Psql([None]))
    assert live_record.stored_scan_record("exc-1", Path(".")) is None
    assert live_record.stored_record("exc-1", Path(".")) is None

    monkeypatch.setattr(live_record.subprocess, "run", _Psql(["not json"]))
    with pytest.raises(live_record.StoredRecordError, match="unreadable database row"):
        live_record.stored_scan_record("exc-1", Path("."))

    monkeypatch.setattr(live_record.subprocess, "run", _Psql(["[1, 2]"]))
    with pytest.raises(live_record.StoredRecordError, match="unreadable database row"):
        live_record.stored_record("exc-1", Path("."))


def test_unique_reading_takes_a_response_and_a_note_and_a_fresh_identity(
    baseline: Path,
) -> None:
    """The fixture's note stays unless a note is given; a response is set only when given."""
    plain = live_record.unique_reading()
    assert plain["handling_note"] == BASELINE_NOTE
    assert "emulator_response" not in plain
    assert plain["reading_id"].startswith("reading-auth-")
    assert plain["shipment_id"].startswith("shipment-auth-")

    chosen = live_record.unique_reading(
        response="pii-echo", prefix="scan", note="hold at the relay"
    )
    assert chosen["emulator_response"] == "pii-echo"
    assert chosen["handling_note"] == "hold at the relay"
    assert chosen["reading_id"].startswith("reading-scan-")
    assert chosen["reading_id"] != plain["reading_id"]
    assert chosen["recorded_at"] != "2026-01-01T00:00:00Z"


class _Response:
    """A minimal accepted-reading response."""

    def __init__(self, body: Any) -> None:
        self.body = body

    def raise_for_status(self) -> None:
        """Accept."""

    def json(self) -> Any:
        """Return the scripted body."""
        return self.body


class _Client:
    """Record the one intake request and answer with the scripted body."""

    def __init__(self, body: Any) -> None:
        self.body = body
        self.posts: list[tuple[str, dict[str, Any]]] = []
        self.headers: list[dict[str, str] | None] = []

    def post(
        self, path: str, *, json: dict[str, Any], headers: dict[str, str] | None = None
    ) -> _Response:
        """Record and answer."""
        self.posts.append((path, json))
        self.headers.append(headers)
        return _Response(self.body)


def test_create_stored_exception_submits_through_the_open_intake_then_waits(
    monkeypatch: pytest.MonkeyPatch, no_sleep: None, baseline: Path
) -> None:
    """The reading goes to the intake without a token; the id returned is the one waited for."""
    client = _Client({"exception_id": "exc-feedbeef", "state": "RECEIVED", "status_url": "/x"})
    psql = _Psql(["COMPLETED|80"])
    monkeypatch.setattr(live_record.subprocess, "run", psql)

    exception_id = live_record.create_stored_exception(
        client,  # type: ignore[arg-type]
        root=Path("."),
    )

    assert exception_id == "exc-feedbeef"
    [(path, reading)] = client.posts
    assert path == "/api/v1/readings"
    assert reading["reading_id"].startswith("reading-auth-")
    assert reading["handling_note"] == BASELINE_NOTE
    [sent] = client.headers
    assert sent is not None and sent["traceparent"].startswith("00-")
    assert "exc-feedbeef" in psql.commands[0][-1]

    unusable = _Client({"detail": "nope"})
    with pytest.raises(live_record.StoredRecordError, match="no usable exception id"):
        live_record.submit_reading(unusable)  # type: ignore[arg-type]


def test_a_traced_submission_carries_the_note_the_response_and_the_chosen_trace(
    baseline: Path,
) -> None:
    """What was sent comes back: the reading with its note and response, in the given trace."""
    client = _Client({"exception_id": "exc-0123abcd", "state": "RECEIVED", "status_url": "/x"})

    submission = live_record.submit_traced_reading(
        client,  # type: ignore[arg-type]
        response="pii-echo",
        trace_id=TRACE_ID,
        note="hold at the relay",
    )

    assert submission.exception_id == "exc-0123abcd"
    assert submission.trace_id == TRACE_ID
    [(path, reading)] = client.posts
    assert path == "/api/v1/readings"
    assert reading is submission.reading
    assert reading["handling_note"] == "hold at the relay"
    assert reading["emulator_response"] == "pii-echo"
    assert submission.reading_id == reading["reading_id"]
    [sent] = client.headers
    assert sent is not None
    assert re.fullmatch("00-" + TRACE_ID + "-[0-9a-f]{16}-01", sent["traceparent"])

    fresh = live_record.submit_traced_reading(
        _Client({"exception_id": "exc-4567cdef"}),  # type: ignore[arg-type]
    )
    assert re.fullmatch(r"[0-9a-f]{32}", fresh.trace_id) and fresh.trace_id != TRACE_ID
    assert fresh.reading["handling_note"] == BASELINE_NOTE
    assert "emulator_response" not in fresh.reading


def test_create_finished_submission_waits_for_any_finished_state(
    monkeypatch: pytest.MonkeyPatch, no_sleep: None, baseline: Path
) -> None:
    """The submission and the finished state come back together; a refusal is not an error."""
    client = _Client({"exception_id": "exc-89abcdef", "state": "RECEIVED", "status_url": "/x"})
    monkeypatch.setattr(live_record.subprocess, "run", _Psql(["QUEUED|0", "NEEDS_REVIEW|40"]))

    submission, state = live_record.create_finished_submission(
        client,  # type: ignore[arg-type]
        response="malformed",
        note="hold at the relay",
        root=Path("."),
    )

    assert (submission.exception_id, state) == ("exc-89abcdef", "NEEDS_REVIEW")
    assert submission.reading["emulator_response"] == "malformed"
    assert submission.reading["handling_note"] == "hold at the relay"
