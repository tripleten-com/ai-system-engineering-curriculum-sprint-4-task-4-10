"""Coldline.

===================

File:              tests/unit/worker/test_model_request.py
Component:         Unit tests — Model request record reader
Purpose:           Prove `python -m worker.model_request` prints a recorded request, says when
                    none exists, and says when the worker records nothing at all.
Interacts With:    src/worker/model_request.py, src/adapters/model/request_log.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.4
Concepts:          Reading what crossed a trust boundary, from the receiving side
Tools:             Python 3.12, pytest
"""

from pathlib import Path

import pytest

from adapters.model.request_log import FileModelRequestLog
from worker import model_request


def _environment(monkeypatch: pytest.MonkeyPatch, directory: Path | None) -> None:
    """Set the worker's required environment, with or without a request directory."""
    monkeypatch.setenv("COLDLINE_DATABASE_URL", "postgresql://user:pass@postgres:5432/coldline")
    monkeypatch.setenv("COLDLINE_REDIS_URL", "redis://redis:6379/0")
    monkeypatch.setenv("COLDLINE_OTEL_ENDPOINT", "http://jaeger:4317")
    monkeypatch.delenv("COLDLINE_MODEL_REQUEST_DIR", raising=False)
    if directory is not None:
        monkeypatch.setenv("COLDLINE_MODEL_REQUEST_DIR", str(directory))


def test_a_recorded_request_is_printed_as_it_was_recorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The record for the id is printed whole; the directory comes from the settings."""
    FileModelRequestLog(tmp_path).record("exc-1234", '{"handling_note": "as received"}')
    _environment(monkeypatch, tmp_path)

    assert model_request.main(["exc-1234"]) == 0

    assert capsys.readouterr().out.strip() == '{"handling_note": "as received"}'


def test_a_missing_record_and_a_bad_id_are_reported(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """No record is exit 1 with the id named; an id that is not an id is exit 2."""
    assert model_request.main(["exc-absent"], request_dir=str(tmp_path)) == 1
    assert "no model request recorded for exception exc-absent" in capsys.readouterr().err

    assert model_request.main(["../escape"], request_dir=str(tmp_path)) == 2
    assert "refusing to record" in capsys.readouterr().err


def test_a_worker_without_a_request_directory_says_so(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Without COLDLINE_MODEL_REQUEST_DIR there is nothing to read, and the exit says why."""
    _environment(monkeypatch, None)

    assert model_request.main(["exc-1234"]) == 2

    assert "COLDLINE_MODEL_REQUEST_DIR is not set" in capsys.readouterr().err
