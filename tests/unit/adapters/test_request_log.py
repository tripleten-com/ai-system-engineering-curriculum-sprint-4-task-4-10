"""Coldline.

===================

File:              tests/unit/adapters/test_request_log.py
Component:         Unit tests — Model request log
Purpose:           Prove the request record is the request as received, kept per exception, on
                    disk or in memory, and that only an exception id becomes a file name.
Interacts With:    src/adapters/model/request_log.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.4
Concepts:          Observable boundaries, one record per exception
Tools:             Python 3.12, pytest
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from adapters.model.request_log import (
    FileModelRequestLog,
    MemoryModelRequestLog,
    record_path,
    request_text,
)
from domain.contracts import ModelRequest

REQUEST = ModelRequest(
    exception_id="exc-0123abcd",
    shipment_id="shipment-syn-001",
    temperature_c=9.2,
    allowed_min_c=2.0,
    allowed_max_c=8.0,
    handling_note="Re-ice at the relay before the pallet moves.",
    procedure_id="playbook-thermal-excursion",
    procedure_excerpt="A thermal excursion begins the moment a probe reports a reading.",
    emulator_response="valid",
)


def test_the_request_text_is_the_whole_request_as_sorted_json() -> None:
    """Every field the provider received is in the text, under its name, keys sorted."""
    text = request_text(REQUEST)

    loaded = json.loads(text)
    assert loaded["handling_note"] == REQUEST.handling_note
    assert loaded["procedure_excerpt"] == REQUEST.procedure_excerpt
    assert loaded["emulator_response"] == "valid"
    assert list(loaded) == sorted(loaded)
    assert request_text(REQUEST) == text


def test_the_file_log_writes_one_file_per_exception_and_reads_it_back(tmp_path: Path) -> None:
    """A record lands under `<exception_id>.json`, replaces an earlier one, and reads back."""
    log = FileModelRequestLog(tmp_path / "requests")
    assert log.directory == tmp_path / "requests"
    assert log.text_for("exc-0123abcd") is None

    log.record("exc-0123abcd", "first")
    log.record("exc-0123abcd", request_text(REQUEST))

    assert (tmp_path / "requests/exc-0123abcd.json").is_file()
    assert log.text_for("exc-0123abcd") == request_text(REQUEST)
    assert log.text_for("exc-other") is None


def test_the_memory_log_keeps_the_records_in_a_dictionary() -> None:
    """The harness's log holds the text under the exception id and nothing else."""
    log = MemoryModelRequestLog()

    log.record("exc-1", "one")
    log.record("exc-2", "two")

    assert log.text_for("exc-1") == "one"
    assert log.text_for("exc-2") == "two"
    assert log.text_for("exc-3") is None
    assert log.records == {"exc-1": "one", "exc-2": "two"}


@pytest.mark.parametrize("bad", ["", "../escape", "exc 1", "a/b", "x" * 121])
def test_only_an_identity_shaped_id_becomes_a_record_name(tmp_path: Path, bad: str) -> None:
    """A path separator, a space, an empty id, or an over-long one is refused, not written."""
    with pytest.raises(ValueError, match="refusing to record"):
        record_path(tmp_path, bad)
    with pytest.raises(ValueError, match="refusing to record"):
        FileModelRequestLog(tmp_path).record(bad, "text")
    with pytest.raises(ValueError, match="refusing to record"):
        MemoryModelRequestLog().record(bad, "text")
    assert list(tmp_path.iterdir()) == []
