"""Coldline.

===================

File:              tests/unit/worker/test_provider_auth.py
Component:         Unit tests — Provider authentication record reader
Purpose:           Prove `poe provider-auth-check` prints the last authenticated version by id
                    and fingerprint, reports a refusal, exits 1 before any authentication, and
                    never prints a value.
Interacts With:    src/worker/provider_auth.py, src/adapters/model/provider_keys.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          Evidence by version id and fingerprint
Tools:             Python 3.12, pytest
"""

import json
from pathlib import Path

import pytest

from adapters.model.provider_keys import (
    ACCEPTED,
    REJECTED,
    AuthenticationOutcome,
    FileAuthenticationRecord,
)
from worker import provider_auth

ACCEPTED_A = AuthenticationOutcome(
    ACCEPTED, "version-a", "0123456789ab", "2026-10-05T12:00:00+00:00", "current version"
)


def _record(path: Path, *outcomes: AuthenticationOutcome) -> str:
    record = FileAuthenticationRecord(path)
    for outcome in outcomes:
        record.record(outcome)
    return str(path)


def test_no_record_yet_exits_one_with_the_hint(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Before the first scenario the check says so and exits 1."""
    assert provider_auth.main([], record_path=str(tmp_path / "record.json")) == 1
    assert "run `poe scenario` first" in capsys.readouterr().err


def test_no_record_file_configured_exits_two(capsys: pytest.CaptureFixture[str]) -> None:
    """A worker that keeps no record is a configuration problem, exit 2."""
    assert provider_auth.main([], record_path="") == 2
    assert "COLDLINE_PROVIDER_AUTH_RECORD" in capsys.readouterr().err


def test_the_last_accepted_version_is_printed_by_id_and_fingerprint(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The accepted version's id, fingerprint and time are printed; no value is anywhere."""
    path = _record(
        tmp_path / "record.json",
        ACCEPTED_A,
    )

    assert provider_auth.main([], record_path=path) == 0
    out = capsys.readouterr().out
    assert "version-a" in out and "0123456789ab" in out and "2026-10-05T12:00:00" in out
    assert "rejected" not in out


def test_a_newer_refusal_is_reported_after_the_last_accepted_version(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A refusal after the last acceptance is printed with its reason, below the accepted line."""
    path = _record(
        tmp_path / "record.json",
        ACCEPTED_A,
        AuthenticationOutcome(
            REJECTED,
            "version-a",
            "0123456789ab",
            "2026-10-05T12:05:00+00:00",
            "the presented key is version version-a, which was replaced",
        ),
    )

    assert provider_auth.main([], record_path=path) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].startswith(
        "provider-auth-check: the worker last authenticated with version version-a"
    )
    assert "was rejected" in lines[1] and "which was replaced" in lines[1]


def test_only_refusals_so_far_exit_one_naming_the_reason(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A worker never accepted exits 1 and says why the most recent attempt was refused."""
    path = _record(
        tmp_path / "record.json",
        AuthenticationOutcome(
            REJECTED, None, "0123456789ab", "2026-10-05T12:05:00+00:00", "no version"
        ),
    )

    assert provider_auth.main([], record_path=path) == 1
    assert "was rejected: no version" in capsys.readouterr().err


def test_json_prints_both_outcomes_for_the_checks(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`--json` prints the record's two documents; exit 1 without an accepted one."""
    path = _record(
        tmp_path / "record.json",
        ACCEPTED_A,
    )

    assert provider_auth.main(["--json"], record_path=path) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["last_accepted"]["version_id"] == "version-a"
    assert document["last_attempt"]["outcome"] == ACCEPTED

    assert provider_auth.main(["--json"], record_path=str(tmp_path / "none.json")) == 1
    assert json.loads(capsys.readouterr().out) == {"last_accepted": None, "last_attempt": None}
