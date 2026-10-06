"""Coldline.

===================

File:              tests/conftest.py
Component:         Test session hooks
Purpose:           Print every queue-forcing timing line once, in the pytest terminal summary.
Interacts With:    tests/failure/forcing_timing.py, the queue helpers and their runtime checks
Sprint/Task:       Sprint 3 — Project 3
Concepts:          Evidence, dead-letter redrive, CI diagnostics
Tools:             Python 3.12, pytest

pytest hides a passing test's output, so a queue helper that runs inside a test
cannot print its timing line directly and still have it reach the CI job log.
The helpers hand the line to ``tests.failure.forcing_timing`` instead, and this
hook prints what was collected once the session ends, pass or fail.
"""

from typing import Any

from tests.failure import forcing_timing


def pytest_configure(config: Any) -> None:
    """Collect timing lines for the summary instead of printing them mid-test."""
    forcing_timing.start_collecting()


def pytest_terminal_summary(terminalreporter: Any) -> None:
    """Print each collected timing line exactly once."""
    lines = forcing_timing.collected()
    if not lines:
        return
    terminalreporter.write_sep("-", "queue forcing")
    for line in lines:
        terminalreporter.write_line(line)
