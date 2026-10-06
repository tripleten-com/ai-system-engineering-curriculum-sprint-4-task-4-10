"""Coldline.

===================

File:              tests/unit/api/test_audit_trail.py
Component:         Unit tests — Audit trail command
Purpose:           Prove `poe audit-trail` prints every record in order, as a table or as JSON
                    lines, without a database.
Interacts With:    src/api/audit_trail.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.3
Concepts:          Reconstructing one interaction from its records
Tools:             Python 3.12, pytest
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from api import audit_trail
from common.audit import AuditRecord

NOW = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
RECORDS = [
    AuditRecord("processing_requested", "exc-1", "a" * 32, NOW, {"reading_id": "r-1"}, 1),
    AuditRecord("model_responded", "exc-1", "a" * 32, NOW, {"answer_length": 10}, 2),
    AuditRecord("summary_read", "exc-1", "b" * 32, NOW, {"subject": "user:d", "role": "d"}, 3),
]


def test_the_table_lists_every_record_in_order_with_its_trace_id() -> None:
    """One row per record: position, event, exception id, trace id, time, details."""
    table = audit_trail.render_table(RECORDS)

    lines = table.splitlines()
    assert lines[0].startswith("| # | event | exception_id | trace_id | recorded_at | details |")
    assert lines[2].startswith("| 1 | `processing_requested` | `exc-1` | `" + "a" * 32)
    assert lines[4].startswith("| 3 | `summary_read` | `exc-1` | `" + "b" * 32)
    assert '{"role": "d", "subject": "user:d"}' in lines[4]


def test_main_prints_json_lines_or_a_table(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """`--json` prints one object per record; the table form prints the count and the rows."""

    async def scripted(exception_id: str) -> list[AuditRecord]:
        assert exception_id == "exc-1"
        return list(RECORDS)

    monkeypatch.setattr(audit_trail, "trail_for", scripted)

    assert audit_trail.main(["--json", "exc-1"]) == 0
    printed = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line]
    assert [record["event"] for record in printed] == [
        "processing_requested",
        "model_responded",
        "summary_read",
    ]
    assert printed[2]["details"] == {"subject": "user:d", "role": "d"}

    assert audit_trail.main(["exc-1"]) == 0
    output = capsys.readouterr().out
    assert "exception_id: exc-1" in output and "events: 3" in output
    assert "`summary_read`" in output


def test_main_reports_an_empty_trail(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """No records is exit 1 with a message in table form, and no lines in JSON form."""

    async def nothing(exception_id: str) -> list[AuditRecord]:
        return []

    monkeypatch.setattr(audit_trail, "trail_for", nothing)

    assert audit_trail.main(["exc-none"]) == 1
    assert "no audit records for exception exc-none" in capsys.readouterr().out
    assert audit_trail.main(["--json", "exc-none"]) == 0
    assert capsys.readouterr().out == ""
