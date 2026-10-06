"""Coldline.

===================

File:              tests/security/live_record.py
Component:         Security tooling — Exceptions through the running stack
Purpose:           Create exceptions through the open intake and read their stored state
                    through a trusted path no student code can refuse or rewrite.
Interacts With:    The running API, worker, and PostgreSQL (Docker Compose),
                    tests/e2e/baseline-exception.json, tests/contract/test_redaction_contract.py,
                    tests/security/pii_scan.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.4
Concepts:          Assessment preconditions, trusted evidence, authorization-independent wait
Tools:             Python 3.12, httpx, Docker Compose, psql

The live assessed rows need two things from the running stack that no student-editable
code may stand between: the moment an exception is finished, and what its record holds.
Waiting through the API's own status URL would read the protected route, and reading the
record through it would add a summary read to the trail the audit rows count. Both are
read inside the ``postgres`` container instead (``docker compose exec -T postgres psql``,
the smoke checks' pattern): the intake is open, the poll needs no token, and the record
comes back as the database holds it.

``wait_for_stored_summary`` and ``create_stored_exception`` keep Task 4.2's semantics
(``COMPLETED`` with a non-empty summary, or an error) for the inherited access-rule row;
``wait_for_finished`` returns whichever finished state the record reached, because for the
output rows a wrong state is the row's finding, not a precondition failure.

The trail rows need to know which request recorded which event, so ``submit_traced_reading``
and ``traceparent`` let the checks send every request with a W3C trace context of their
own choosing: the API's instrumentation continues an incoming ``traceparent``, the worker
continues the API's trace through the queue message, and the audit sink stores the
current trace id, so the ids the checks generated here are the ids the records must carry.

Task 4.4 adds the handling note to what a submission can carry (``note=`` is the note's
text, as a supplied fixture note holds it) and ``stored_scan_record``, the four columns
``poe pii-scan`` needs: the state, the summary, the stored handling note and the response
selector the reading carried.
"""

from __future__ import annotations

import json
import re
import secrets
import subprocess
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast
from uuid import uuid4

if TYPE_CHECKING:
    import httpx

TASK_ROOT = Path(__file__).resolve().parents[2]
BASELINE_PATH = TASK_ROOT / "tests/e2e/baseline-exception.json"
STORED_SUMMARY_WAIT_SECONDS = 30.0
POLL_INTERVAL_SECONDS = 0.5
POLL_TIMEOUT_SECONDS = 30
COMPLETED = "COMPLETED"
FAILED = "FAILED"
NEEDS_REVIEW = "NEEDS_REVIEW"
FINISHED: frozenset[str] = frozenset({COMPLETED, FAILED, NEEDS_REVIEW})
RECORD_COLUMNS = (
    "state",
    "summary",
    "handling_class",
    "next_step",
    "rejection_reason",
    "failure_reason",
)
# The columns the PII scan reads: the response selector lives inside the stored reading.
SCAN_COLUMNS = (
    "state",
    "summary",
    "handling_note",
    "reading->>'emulator_response' AS emulator_response",
)
COMPOSE: tuple[str, ...] = (
    "docker",
    "compose",
    "--profile",
    "observability",
    "--profile",
    "localstack",
)
# The API mints `exc-<hex>` identities; anything else never reaches the query.
_IDENTITY = re.compile(r"^[A-Za-z0-9_.:-]{1,120}$")


class StoredRecordError(RuntimeError):
    """Report that an exception could not be established or read through the database."""


def unique_reading(
    *, response: str | None = None, prefix: str = "auth", note: str | None = None
) -> dict[str, Any]:
    """Return the supplied out-of-range reading with a fresh identity, a response and a note.

    ``note`` replaces the fixture's handling note with the given text when it is not None.
    """
    fixture = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    reading = cast(dict[str, Any], fixture["reading"])
    suffix = uuid4().hex
    reading["reading_id"] = f"reading-{prefix}-{suffix}"
    reading["shipment_id"] = f"shipment-{prefix}-{suffix}"
    reading["recorded_at"] = datetime.now(UTC).isoformat()
    if response is not None:
        reading["emulator_response"] = response
    if note is not None:
        reading["handling_note"] = note
    return reading


@dataclass(frozen=True)
class Submission:
    """One reading the checks submitted: its ids, the reading itself, and its trace id."""

    exception_id: str
    reading: dict[str, Any]
    trace_id: str

    @property
    def reading_id(self) -> str:
        """Return the reading's identity, which the first audit event must name."""
        return str(self.reading["reading_id"])


def new_trace_id() -> str:
    """Return a fresh 32-hex W3C trace id the checks hold for one request."""
    return secrets.token_hex(16)


def traceparent(trace_id: str) -> dict[str, str]:
    """Return the ``traceparent`` header that puts one request in the given sampled trace."""
    return {"traceparent": f"00-{trace_id}-{secrets.token_hex(8)}-01"}


def submit_traced_reading(
    client: httpx.Client,
    *,
    response: str | None = None,
    trace_id: str | None = None,
    note: str | None = None,
) -> Submission:
    """Submit one fresh reading in a trace of the checks' choosing; return what was sent.

    The reading is the supplied out-of-range reading with a fresh identity and, when
    given, the response selector and the handling note; the request carries ``trace_id``
    as its W3C trace context (a fresh one when none is given), so the worker's events must
    carry it.
    """
    reading = unique_reading(response=response, note=note)
    trace = trace_id if trace_id is not None else new_trace_id()
    accepted = client.post("/api/v1/readings", json=reading, headers=traceparent(trace))
    accepted.raise_for_status()
    body = accepted.json()
    exception_id = body.get("exception_id") if isinstance(body, dict) else None
    if not isinstance(exception_id, str) or not _IDENTITY.match(exception_id):
        raise StoredRecordError(f"the intake returned no usable exception id: {body!r}")
    return Submission(exception_id=exception_id, reading=reading, trace_id=trace)


def submit_reading(client: httpx.Client, *, response: str | None = None) -> str:
    """Submit one fresh reading through the open intake and return its exception id."""
    return submit_traced_reading(client, response=response).exception_id


def _checked(exception_id: str) -> str:
    """Return the id when it has the API's shape, or refuse to put it in a query."""
    if not _IDENTITY.match(exception_id):
        raise StoredRecordError(f"refusing to query an unexpected exception id {exception_id!r}")
    return exception_id


def _query(exception_id: str) -> str:
    """Return the SQL that reads one record's state and summary length."""
    return (
        "SELECT state, coalesce(length(summary), 0) FROM exceptions "
        f"WHERE exception_id = '{_checked(exception_id)}';"
    )


def _record_query(exception_id: str, columns: tuple[str, ...]) -> str:
    """Return the SQL that reads the named columns of one record as one JSON object."""
    selected = ", ".join(columns)
    return (
        f"SELECT row_to_json(t) FROM (SELECT {selected} FROM exceptions "
        f"WHERE exception_id = '{_checked(exception_id)}') t;"
    )


def _psql(sql: str, root: Path) -> str:
    """Run one query inside the postgres container and return its unaligned output."""
    try:
        result = subprocess.run(
            [
                *COMPOSE,
                "exec",
                "-T",
                "postgres",
                "psql",
                "-U",
                "coldline",
                "-d",
                "coldline",
                "-tAc",
                sql,
            ],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=POLL_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise StoredRecordError(f"the database poll could not run: {exc}") from exc
    if result.returncode != 0:
        raise StoredRecordError(
            f"the database poll failed (exit {result.returncode}): {result.stderr.strip()}"
        )
    return result.stdout


def stored_state(exception_id: str, root: Path = TASK_ROOT) -> tuple[str, int] | None:
    """Return ``(state, summary length)`` for one record from the database, or None if absent.

    The query runs inside the ``postgres`` container through Compose, as the smoke checks
    do, so it needs no published database port and no API authorization.
    """
    line = _psql(_query(exception_id), root).strip().splitlines()
    if not line:
        return None
    state, _, length = line[-1].partition("|")
    try:
        return state.strip(), int(length.strip() or "0")
    except ValueError as exc:
        raise StoredRecordError(f"unreadable database row {line[-1]!r}") from exc


def _json_record(exception_id: str, columns: tuple[str, ...], root: Path) -> dict[str, Any] | None:
    """Return the named columns of one record as a dictionary, or None when it is absent."""
    lines = _psql(_record_query(exception_id, columns), root).strip().splitlines()
    if not lines:
        return None
    try:
        loaded = json.loads(lines[-1])
    except ValueError as exc:
        raise StoredRecordError(f"unreadable database row {lines[-1]!r}") from exc
    if not isinstance(loaded, dict):
        raise StoredRecordError(f"unreadable database row {lines[-1]!r}")
    return cast(dict[str, Any], loaded)


def stored_record(exception_id: str, root: Path = TASK_ROOT) -> dict[str, Any] | None:
    """Return one record's output fields (``RECORD_COLUMNS``) from the database, or None."""
    return _json_record(exception_id, RECORD_COLUMNS, root)


def stored_scan_record(exception_id: str, root: Path = TASK_ROOT) -> dict[str, Any] | None:
    """Return the columns the PII scan reads (``SCAN_COLUMNS``) from the database, or None."""
    return _json_record(exception_id, SCAN_COLUMNS, root)


def wait_for_stored_summary(
    exception_id: str,
    *,
    wait_seconds: float = STORED_SUMMARY_WAIT_SECONDS,
    root: Path = TASK_ROOT,
) -> None:
    """Block until the record is COMPLETED with a non-empty summary, or raise saying why not."""
    deadline = time.monotonic() + wait_seconds
    last: tuple[str, int] | None = None
    while True:
        last = stored_state(exception_id, root)
        if last is not None:
            state, length = last
            if state == COMPLETED and length > 0:
                return
            if state == FAILED:
                raise StoredRecordError(
                    f"exception {exception_id} reached FAILED, so it has no stored summary; "
                    "run `poe reset` and `poe start`, then retry"
                )
        if time.monotonic() >= deadline:
            seen = (
                "not yet visible" if last is None else f"state {last[0]}, summary length {last[1]}"
            )
            raise StoredRecordError(
                f"exception {exception_id} did not reach COMPLETED with a stored summary within "
                f"{wait_seconds:g} s ({seen}); is the worker running?"
            )
        time.sleep(POLL_INTERVAL_SECONDS)


def wait_for_finished(
    exception_id: str,
    *,
    wait_seconds: float = STORED_SUMMARY_WAIT_SECONDS,
    root: Path = TASK_ROOT,
) -> str:
    """Block until the record is in a finished state and return that state, or raise on timeout.

    ``COMPLETED``, ``NEEDS_REVIEW`` and ``FAILED`` all end the wait: which one the record
    reached is what the output rows assert, so none of them is an error here.
    """
    deadline = time.monotonic() + wait_seconds
    last: tuple[str, int] | None = None
    while True:
        last = stored_state(exception_id, root)
        if last is not None and last[0] in FINISHED:
            return last[0]
        if time.monotonic() >= deadline:
            seen = "not yet visible" if last is None else f"state {last[0]}"
            raise StoredRecordError(
                f"exception {exception_id} did not finish within {wait_seconds:g} s ({seen}); "
                "is the worker running?"
            )
        time.sleep(POLL_INTERVAL_SECONDS)


def create_stored_exception(
    client: httpx.Client,
    *,
    wait_seconds: float = STORED_SUMMARY_WAIT_SECONDS,
    root: Path = TASK_ROOT,
) -> str:
    """Submit one reading and return its exception id once the summary is stored, or raise."""
    exception_id = submit_reading(client)
    wait_for_stored_summary(exception_id, wait_seconds=wait_seconds, root=root)
    return exception_id


def create_finished_exception(
    client: httpx.Client,
    *,
    response: str,
    wait_seconds: float = STORED_SUMMARY_WAIT_SECONDS,
    root: Path = TASK_ROOT,
) -> tuple[str, str]:
    """Submit one reading with a named response and return its id and finished state."""
    exception_id = submit_reading(client, response=response)
    state = wait_for_finished(exception_id, wait_seconds=wait_seconds, root=root)
    return exception_id, state


def create_finished_submission(
    client: httpx.Client,
    *,
    response: str,
    note: str | None = None,
    wait_seconds: float = STORED_SUMMARY_WAIT_SECONDS,
    root: Path = TASK_ROOT,
) -> tuple[Submission, str]:
    """Submit one reading in a fresh trace and return the submission and its finished state."""
    submission = submit_traced_reading(client, response=response, note=note)
    state = wait_for_finished(submission.exception_id, wait_seconds=wait_seconds, root=root)
    return submission, state
