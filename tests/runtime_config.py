"""Coldline.

===================

File:              tests/runtime_config.py
Component:         Runtime verification configuration
Purpose:           Read host-port overrides with Docker Compose-compatible precedence.
Interacts With:    Process environment, local .env, smoke and E2E checks
Sprint/Task:       Sprint 1 — Project 1
Concepts:          Local parity, explicit precedence, bounded configuration
Tools:             Python 3.12
"""

import os
from pathlib import Path

TASK_ROOT = Path(__file__).resolve().parents[1]


def host_port(name: str, default: int, *, root: Path = TASK_ROOT) -> int:
    """Return one valid host port from the shell, `.env`, or the documented default.

    Docker Compose gives the process environment precedence over its local
    `.env` file. Verification tools follow the same order so a port conflict
    does not make startup and diagnostics disagree.
    """
    value = os.getenv(name)
    if value is None:
        value = _dotenv_values(root / ".env").get(name)
    if value is None:
        return default
    try:
        port = int(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer host port") from exc
    if not 1 <= port <= 65_535:
        raise ValueError(f"{name} must be between 1 and 65535")
    return port


def _dotenv_values(path: Path) -> dict[str, str]:
    """Read the simple key-value form used by this Task's local `.env` file."""
    if not path.is_file():
        return {}
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", maxsplit=1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values
