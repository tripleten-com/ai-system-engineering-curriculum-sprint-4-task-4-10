"""Coldline.

===================

File:              tests/security/trace.py
Component:         Security tooling — Executed-request trace
Purpose:           Record what each student test actually did through the harness: which
                    response it ran the worker with, which fixture it read with, and which
                    exception it requested, for the assessed checks to read.
Interacts With:    tests/security/harness.py and tests/security/interaction.py (write),
                    tests/security/guardrail_mutation.py (reads), pytest
Sprint/Task:       Sprint 4 — Project 4 / Task 4.3
Concepts:          Evidence from executed requests, not from source text
Tools:             Python 3.12, json

When the assessed checks run a student file they set ``COLDLINE_ACCESS_TRACE`` to a file
and the harness appends one JSON line per action a test takes through it: a worker run
(``kind: worker``, with the response it asked for and the exception it produced) or a
request through ``harness.bearer_client(...)`` (``kind: read``, with the fixture, the
path, and whether the requested exception is one the harness holds with a stored
outcome). Each line is tagged with the pytest case that made it (from
``PYTEST_CURRENT_TEST``). The checks then know, per collected test, what the test really
did, which is how the guardrail test for each response and the two audit tests are told
apart. Outside such a run the variable is unset and nothing is written.

A case is identified by its full pytest node id: the student file under ``tests/student``,
the class chain if the test is a method, and the function name with its parameter id
(``tests/student/test_audit.py::TestTrail::test_order[a]``). The trace builds it from
``PYTEST_CURRENT_TEST`` and the junit reader rebuilds the same id from a test case's
``classname`` and ``name``, so two tests that share a method name in different classes
stay two cases, as do two parameters of one function.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path

TRACE_VARIABLE = "COLDLINE_ACCESS_TRACE"
CURRENT_TEST_VARIABLE = "PYTEST_CURRENT_TEST"
SUMMARY_ROUTE = "/api/v1/exceptions/"
# Every student file lives here; a case id names the file by this directory and its name.
STUDENT_DIRECTORY = "tests/student"


def trace_path() -> Path | None:
    """Return the trace file the environment names, or None when no run is recording."""
    value = os.environ.get(TRACE_VARIABLE)
    return Path(value) if value else None


def case_id(node_id: str) -> str:
    """Return the full case identity for one pytest node id, or "" for no node id.

    The file component is reduced to the student directory plus the file's name, so the
    id does not depend on the directory pytest took as its root; the class chain, the
    name, and the parameter id are kept exactly.
    """
    if "::" not in node_id:
        return ""
    file_part, rest = node_id.split("::", 1)
    name = file_part.replace("\\", "/").rsplit("/", 1)[-1]
    return f"{STUDENT_DIRECTORY}/{name}::{rest}"


def junit_case_id(classname: str, name: str) -> str:
    """Return the same identity from a junit ``testcase``'s ``classname`` and ``name``.

    pytest writes ``classname`` as the module's dotted path followed by the class chain
    (``tests.student.test_audit.TestTrail``) and ``name`` as the function with its
    parameter id. The module component is the first one that starts with ``test_``; the
    components after it are the class chain. A ``classname`` that names no test module
    is kept whole, so it matches no traced case and is reported rather than mistaken for
    one.
    """
    parts = classname.split(".") if classname else []
    for index, part in enumerate(parts):
        if part.startswith("test_"):
            chain = parts[index + 1 :]
            return "::".join([f"{STUDENT_DIRECTORY}/{part}.py", *chain, name])
    return f"{classname}::{name}" if classname else name


def current_case() -> str:
    """Return the full case identity of the collected test now running.

    pytest sets ``PYTEST_CURRENT_TEST`` to ``<node id> (<phase>)`` for the duration of each
    test; the phase is dropped and the node id is normalised by ``case_id``.
    """
    value = os.environ.get(CURRENT_TEST_VARIABLE, "")
    return case_id(value.rsplit(" (", 1)[0])


def exception_id_of(path: str) -> str | None:
    """Return the exception id a summary-route path names, or None for any other path."""
    if not path.startswith(SUMMARY_ROUTE):
        return None
    remainder = path[len(SUMMARY_ROUTE) :]
    exception_id = remainder.split("/", 1)[0]
    return exception_id or None


def record(path: Path | None, event: Mapping[str, object]) -> None:
    """Append one event to the trace file, tagged with the current test; no file, no write."""
    if path is None:
        return
    line = json.dumps({"case": current_case(), **event}, sort_keys=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def read_events(path: Path) -> list[dict[str, object]]:
    """Return every recorded event, in order; a missing file is an empty trace."""
    if not path.is_file():
        return []
    events: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        loaded = json.loads(line)
        if isinstance(loaded, dict):
            events.append(loaded)
    return events
