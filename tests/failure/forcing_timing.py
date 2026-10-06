"""Coldline.

===================

File:              tests/failure/forcing_timing.py
Component:         Failure tools — Queue-forcing timing line
Purpose:           Record one fixed-format timing line each time a queue helper forces delivery.
Interacts With:    tests/failure/queue_client.py, tests/conftest.py, the queue helpers
Sprint/Task:       Sprint 3 — Project 3
Concepts:          Evidence, dead-letter redrive, CI diagnostics
Tools:             Python 3.12

Each forcing produces exactly one line, in this fixed format:

    queue-forcing helper=<name> first_receive_seconds=<s.s> receives_observed=<n>
    deadline_seconds=<s.s> outcome=<dead_lettered|not_dead_lettered|received>

(one line; wrapped here). CI tooling outside this repository parses it, so the
format is fixed: add a helper or outcome name only together with that parser.

Run by hand, a helper prints the line itself. Under pytest a passing test's
output is hidden, so ``tests/conftest.py`` collects the lines instead and prints
them once in the session's terminal summary, where they reach the CI job log
on passing and failing runs alike.
"""

import re
from collections.abc import Mapping
from typing import Any

PREFIX = "queue-forcing"
HELPERS = ("trigger_alert_load", "force_dlq_arrival", "runtime_adapters")
OUTCOMES = ("dead_lettered", "not_dead_lettered", "received")
LINE_PATTERN = re.compile(
    r"queue-forcing helper=(?P<helper>[a-z_]+)"
    r" first_receive_seconds=(?P<first>\d+\.\d)"
    r" receives_observed=(?P<receives>\d+)"
    r" deadline_seconds=(?P<deadline>\d+\.\d)"
    r" outcome=(?P<outcome>[a-z_]+)"
)

_collected: list[str] | None = None


def format_line(
    *,
    helper: str,
    first_receive_seconds: float,
    receives_observed: int,
    deadline_seconds: float,
    outcome: str,
) -> str:
    """Return the one timing line for a forcing, in the fixed shared format."""
    if helper not in HELPERS:
        raise ValueError(f"unknown queue-forcing helper {helper!r}; expected one of {HELPERS}")
    if outcome not in OUTCOMES:
        raise ValueError(f"unknown queue-forcing outcome {outcome!r}; expected one of {OUTCOMES}")
    return (
        f"{PREFIX} helper={helper} first_receive_seconds={first_receive_seconds:.1f}"
        f" receives_observed={receives_observed} deadline_seconds={deadline_seconds:.1f}"
        f" outcome={outcome}"
    )


def forcing_line(helper: str, forcing: Mapping[str, Any], *, outcome: str) -> str:
    """Build the line from a forcing loop's own evidence.

    A forcing that never received the message waited until its deadline, so
    the line reports the deadline as its first-receive time: the margin then
    reads as zero, and ``receives_observed=0`` says no message arrived.
    """
    deadline = float(forcing["deadline_seconds"])
    first = forcing.get("first_receive_seconds")
    return format_line(
        helper=helper,
        first_receive_seconds=deadline if first is None else float(first),
        receives_observed=int(forcing["receives_observed"]),
        deadline_seconds=deadline,
        outcome=outcome,
    )


def start_collecting() -> None:
    """Hold lines for the pytest terminal summary instead of printing them."""
    global _collected
    _collected = []


def collected() -> list[str]:
    """Return the lines held so far, in the order they were emitted."""
    return list(_collected or [])


def emit(line: str) -> None:
    """Print the line, or hold it for the summary when running under pytest."""
    if _collected is None:
        print(line, flush=True)
    else:
        _collected.append(line)


def relay(output: str) -> None:
    """Emit every whole timing line a subprocess printed, and nothing else."""
    for raw in output.splitlines():
        line = raw.strip()
        if LINE_PATTERN.fullmatch(line):
            emit(line)


def without_timing_lines(output: str) -> str:
    """Return subprocess output with its timing lines removed, for a failure message."""
    return "\n".join(raw for raw in output.splitlines() if not LINE_PATTERN.fullmatch(raw.strip()))
