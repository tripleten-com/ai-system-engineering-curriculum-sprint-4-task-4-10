"""Coldline.

===================

File:              tests/unit/security/test_issuer_origin.py
Component:         Unit tests — host-side issuer origin
Purpose:           The host origin follows the effective issuer port, read from the environment
                   or from a `.env` file as Compose reads it, and is a valid port.
Interacts With:    tests/security/issuer_origin.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.3
Concepts:          Port overrides, dotenv parsing
Tools:             Python 3.12, pytest
"""

from pathlib import Path

import pytest

from tests.security import issuer_origin


def test_default_port_without_environment_or_env_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Nothing set: the default issuer port."""
    monkeypatch.delenv(issuer_origin.PORT_VARIABLE, raising=False)
    assert issuer_origin.host_issuer_origin(tmp_path) == "http://localhost:8180"


def test_env_file_port_is_used(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A remapped port in .env moves the host origin."""
    monkeypatch.delenv(issuer_origin.PORT_VARIABLE, raising=False)
    (tmp_path / ".env").write_text("COLDLINE_ISSUER_HOST_PORT=28180\n", encoding="utf-8")
    assert issuer_origin.host_issuer_origin(tmp_path) == "http://localhost:28180"


def test_environment_wins_over_env_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The process environment overrides .env."""
    (tmp_path / ".env").write_text("COLDLINE_ISSUER_HOST_PORT=28180\n", encoding="utf-8")
    monkeypatch.setenv(issuer_origin.PORT_VARIABLE, "38180")
    assert issuer_origin.host_issuer_origin(tmp_path) == "http://localhost:38180"


@pytest.mark.parametrize(
    "line",
    [
        'COLDLINE_ISSUER_HOST_PORT="28180"',
        "COLDLINE_ISSUER_HOST_PORT='28180'",
        "COLDLINE_ISSUER_HOST_PORT=28180 # the local override",
        'COLDLINE_ISSUER_HOST_PORT="28180" # quoted and commented',
        "export COLDLINE_ISSUER_HOST_PORT=28180",
        "  COLDLINE_ISSUER_HOST_PORT = 28180  ",
    ],
    ids=["double-quoted", "single-quoted", "inline-comment", "quoted-comment", "export", "spaces"],
)
def test_env_file_values_are_read_as_compose_reads_them(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, line: str
) -> None:
    """Quotes are removed, an inline comment is cut, `export` and spaces are tolerated."""
    monkeypatch.delenv(issuer_origin.PORT_VARIABLE, raising=False)
    (tmp_path / ".env").write_text(
        f"# Coldline local overrides\n\nCOLDLINE_API_HOST_PORT=18000\n{line}\n", encoding="utf-8"
    )
    assert issuer_origin.effective_issuer_port(tmp_path) == "28180"
    assert issuer_origin.host_issuer_origin(tmp_path) == "http://localhost:28180"


def test_the_last_assignment_wins_and_other_names_are_ignored(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A later line for the same name replaces an earlier one; unrelated names change nothing."""
    monkeypatch.delenv(issuer_origin.PORT_VARIABLE, raising=False)
    (tmp_path / ".env").write_text(
        "COLDLINE_ISSUER_HOST_PORT=28180\nCOLDLINE_ISSUER_HOST_PORT_OLD=1\n"
        "COLDLINE_ISSUER_HOST_PORT=28181\nNOT_AN_ASSIGNMENT\n",
        encoding="utf-8",
    )
    values = issuer_origin.env_file_values(tmp_path / ".env")
    assert values["COLDLINE_ISSUER_HOST_PORT"] == "28181"
    assert values["COLDLINE_ISSUER_HOST_PORT_OLD"] == "1"
    assert issuer_origin.host_issuer_origin(tmp_path) == "http://localhost:28181"


def test_a_blank_env_file_value_falls_back_to_the_default(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """`COLDLINE_ISSUER_HOST_PORT=` and `=""` set nothing, as an unset variable does."""
    monkeypatch.delenv(issuer_origin.PORT_VARIABLE, raising=False)
    (tmp_path / ".env").write_text('COLDLINE_ISSUER_HOST_PORT=""\n', encoding="utf-8")
    assert issuer_origin.host_issuer_origin(tmp_path) == "http://localhost:8180"
    (tmp_path / ".env").write_text("COLDLINE_ISSUER_HOST_PORT=\n", encoding="utf-8")
    assert issuer_origin.host_issuer_origin(tmp_path) == "http://localhost:8180"


@pytest.mark.parametrize("value", ["eighty", "8180x", "0", "65536", "-1", "81 80"])
def test_a_port_that_is_not_an_integer_in_range_is_refused_by_name(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, value: str
) -> None:
    """A bad value is an error naming the variable and its source, never a malformed URL."""
    monkeypatch.setenv(issuer_origin.PORT_VARIABLE, value)
    with pytest.raises(issuer_origin.IssuerPortError, match="the environment"):
        issuer_origin.host_issuer_origin(tmp_path)

    monkeypatch.delenv(issuer_origin.PORT_VARIABLE, raising=False)
    (tmp_path / ".env").write_text(f"COLDLINE_ISSUER_HOST_PORT={value}\n", encoding="utf-8")
    with pytest.raises(issuer_origin.IssuerPortError, match=r"\.env"):
        issuer_origin.host_issuer_origin(tmp_path)


def test_a_missing_env_file_is_an_empty_mapping(tmp_path: Path) -> None:
    """No file, no values."""
    assert issuer_origin.env_file_values(tmp_path / ".env") == {}
