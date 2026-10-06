"""Coldline.

===================

File:              tests/security/pii_scan.py
Component:         Security tooling — PII scan over the running stack
Purpose:           Search one exception's worker logs, model request, audit records and stored
                    summary for the marked values of its note and its response, and print what
                    was found where.
Interacts With:    The running worker, API and PostgreSQL (Docker Compose),
                    tests/security/pii.py, tests/security/live_record.py, tests/security/trail.py,
                    src/worker/model_request.py, tests/contract/test_redaction_contract.py,
                    pyproject.toml (`poe pii-scan`)
Sprint/Task:       Sprint 4 — Project 4 / Task 4.4
Concepts:          Evidence per trust boundary, a search bounded to marked values
Tools:             Python 3.12, Docker Compose

``poe pii-scan <exception_id>`` reads the exception's record through the database (its
state, summary, handling note and response selector), decides which marked values apply
(the supplied note whose text the record holds exactly, and the supplied response), reads
the four locations, and prints one line per location: what it found (by the marked
value's label, ``N-01 phone``, never the value itself, so the scan's output is not one
more place the detail reaches), ``clean``, or ``unavailable``. The redaction report is
where the values are printed, on purpose. It exits 1 when any marked value was found, 0
when none was and every
location was read, and 2 when a location could not be read or is not there to read: a
finished run whose request record is gone or whose worker logs hold no line naming the
exception (the worker container was recreated since, for example) is reported
``unavailable`` for that location, never ``clean``, because absence cannot be shown from
evidence that is not there. The four locations:

- the worker logs: ``docker compose logs worker``, the lines that name the exception;
- the model request: ``python -m worker.model_request <id>`` inside the worker container,
  the text the emulator recorded when it received the request;
- the audit records: the exception's trail, as ``poe audit-trail --json`` prints it, each
  record's ``details`` rendered as JSON;
- the stored summary: the record's ``summary`` column.

A handling note that is not one of the supplied notes (the default scenario reading's,
for example) has no marked values, and the scan says so instead of guessing; run the
scenario with ``--note <id>`` to scan a note's values.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from tests.security import pii, trail
from tests.security.live_record import COMPOSE, StoredRecordError, stored_scan_record

TASK_ROOT = Path(__file__).resolve().parents[2]
COMMAND_TIMEOUT_SECONDS = 60
MODEL_REQUEST_COMMAND: tuple[str, ...] = ("python", "-m", "worker.model_request")
UNAVAILABLE = "unavailable"
# What each location's absence means, for the report.
UNAVAILABLE_REASONS = {
    "worker logs": "no worker log line names this exception (was the worker recreated?)",
    "model request": "no request record for this exception (was the worker recreated?)",
}


def worker_logs(exception_id: str, root: Path = TASK_ROOT) -> str:
    """Return the worker container's log lines that name the exception, as one text."""
    try:
        result = subprocess.run(
            [*COMPOSE, "logs", "--no-color", "worker"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise StoredRecordError(f"the worker logs could not be read: {exc}") from exc
    if result.returncode != 0:
        raise StoredRecordError(
            f"the worker logs could not be read (exit {result.returncode}): {result.stderr.strip()}"
        )
    return "\n".join(line for line in result.stdout.splitlines() if exception_id in line)


def model_request(exception_id: str, root: Path = TASK_ROOT) -> str | None:
    """Return the request text the emulator recorded for the exception, or None when none."""
    try:
        result = subprocess.run(
            [*COMPOSE, "exec", "-T", "worker", *MODEL_REQUEST_COMMAND, exception_id],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise StoredRecordError(f"the model request could not be read: {exc}") from exc
    if result.returncode == 1:
        return None
    if result.returncode != 0:
        raise StoredRecordError(
            f"the model request could not be read (exit {result.returncode}): "
            f"{result.stderr.strip()}"
        )
    return result.stdout


def live_locations(exception_id: str, root: Path = TASK_ROOT) -> dict[str, str | None]:
    """Return the four locations' text for one exception, read from the running stack.

    A location whose evidence is not there to read is None, never empty text: worker
    logs with no line naming the exception, and a model request that was never recorded
    or whose record is gone. ``pii.findings`` reports nothing for a None location, and the
    callers say it was unavailable; a scan over it cannot show absence.
    """
    record = stored_scan_record(exception_id, root)
    if record is None:
        raise StoredRecordError(f"exception {exception_id} is not in the database")
    request = model_request(exception_id, root)
    records = trail.fetch_trail(exception_id, root)
    summary = record.get("summary")
    return {
        "worker logs": worker_logs(exception_id, root) or None,
        "model request": request or None,
        "audit records": pii.details_text(trail.details_of(item) for item in records),
        "stored summary": summary if isinstance(summary, str) else "",
    }


def unavailable_locations(locations: Mapping[str, str | None]) -> list[str]:
    """Return the locations that could not be read, in report order."""
    return [location for location in pii.LOCATIONS if locations.get(location) is None]


def applicable_values(
    record: Mapping[str, Any], notes: Mapping[str, pii.Note]
) -> tuple[pii.Note | None, str | None, tuple[pii.MarkedValue, ...]]:
    """Return the note the record holds (if supplied), its response, and the marked values."""
    handling_note = record.get("handling_note")
    note = pii.note_for_text(handling_note if isinstance(handling_note, str) else None, notes)
    response = record.get("emulator_response")
    response_name = response if isinstance(response, str) else None
    values = list(note.marked) if note is not None else []
    values.extend(pii.response_values(response_name))
    return note, response_name, tuple(values)


def report(
    exception_id: str,
    record: Mapping[str, Any],
    note: pii.Note | None,
    response: str | None,
    values: Sequence[pii.MarkedValue],
    locations: Mapping[str, str | None],
    found: Sequence[pii.Finding],
) -> list[str]:
    """Render the scan's output: the run, the marked values, and one line per location.

    A finding is printed as its label (``N-01 phone``), never as the value found. A
    location that could not be read is ``unavailable`` with the reason, never ``clean``,
    and the closing line says the scan is incomplete.
    """
    lines = [f"pii-scan: exception {exception_id}", f"  state: {record.get('state')}"]
    if note is None:
        lines.append(
            "  handling note: not a supplied fixture note (no note values searched; run "
            "`poe scenario --note <id>` to scan a supplied note)"
        )
    else:
        lines.append(f"  handling note: {note.note_id} ({len(note.marked)} marked value(s))")
    response_count = len(pii.response_values(response))
    lines.append(f"  response: {response or 'valid'} ({response_count} marked value(s))")
    unavailable = unavailable_locations(locations)
    for location in pii.LOCATIONS:
        here = [item for item in found if item.location == location]
        if location in unavailable:
            reason = UNAVAILABLE_REASONS.get(location, "could not be read")
            lines.append(f"  {location}: {UNAVAILABLE} ({reason})")
        elif here:
            listed = ", ".join(item.label for item in here)
            lines.append(f"  {location}: found {listed}")
        else:
            lines.append(f"  {location}: clean")
    if not values:
        lines.append("pii-scan: no marked values to search for")
    elif found:
        places = len({item.location for item in found})
        lines.append(f"pii-scan: {len(found)} marked value(s) found in {places} location(s)")
    else:
        searched = "the searched locations" if unavailable else "any location"
        lines.append(f"pii-scan: no marked value found in {searched}")
    if unavailable:
        lines.append(
            f"pii-scan: incomplete; {len(unavailable)} location(s) {UNAVAILABLE} "
            f"({', '.join(unavailable)}); absence cannot be shown for this run"
        )
    return lines


def main(argv: Sequence[str] | None = None) -> int:
    """Scan one exception and print the result.

    Exit 1 on a finding, 2 on a tooling error or an unavailable location (the lines for
    the locations that were read are still printed), 0 only when every location was read
    and none held a marked value.
    """
    parser = argparse.ArgumentParser(
        description="Search one exception's four locations for its marked PII values."
    )
    parser.add_argument("exception_id", help="the exception id `poe scenario` printed")
    parser.add_argument("--root", type=Path, default=TASK_ROOT)
    arguments = parser.parse_args(argv)
    try:
        notes = pii.load_notes(arguments.root)
        record = stored_scan_record(arguments.exception_id, arguments.root)
        if record is None:
            raise StoredRecordError(f"exception {arguments.exception_id} is not in the database")
        note, response, values = applicable_values(record, notes)
        locations = live_locations(arguments.exception_id, arguments.root)
    except (StoredRecordError, ValueError) as exc:
        print(f"pii-scan: {exc}", file=sys.stderr)
        return 2
    found = pii.findings(locations, values)
    for line in report(arguments.exception_id, record, note, response, values, locations, found):
        print(line)
    if unavailable_locations(locations):
        return 2
    return 1 if found else 0


if __name__ == "__main__":
    raise SystemExit(main())
