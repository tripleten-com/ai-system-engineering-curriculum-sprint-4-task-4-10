"""Coldline.

===================

File:              tests/unit/test_runtime_config.py
Component:         Unit tests — Runtime host configuration
Purpose:           Keep Compose and verification host-port overrides aligned.
Interacts With:    Process environment, local .env, runtime test helpers
Sprint/Task:       Sprint 1 — Project 1
Concepts:          Local parity, explicit precedence, deterministic configuration
Tools:             Python 3.12, pytest
"""

from pathlib import Path

import pytest

from tests.runtime_config import host_port


def test_host_port_reads_dotenv_when_shell_value_is_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Match the `.env` interpolation that Docker Compose applies automatically."""
    monkeypatch.delenv("COLDLINE_API_HOST_PORT", raising=False)
    (tmp_path / ".env").write_text("COLDLINE_API_HOST_PORT=18000\n", encoding="utf-8")

    assert host_port("COLDLINE_API_HOST_PORT", 8000, root=tmp_path) == 18000


def test_shell_host_port_overrides_dotenv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Use the same process-environment precedence as Docker Compose."""
    monkeypatch.setenv("COLDLINE_API_HOST_PORT", "19000")
    (tmp_path / ".env").write_text("COLDLINE_API_HOST_PORT=18000\n", encoding="utf-8")

    assert host_port("COLDLINE_API_HOST_PORT", 8000, root=tmp_path) == 19000
