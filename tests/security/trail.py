"""Coldline.

===================

File:              tests/security/trail.py
Component:         Security tooling — Audit trail reader and rules
Purpose:           Read one exception's audit trail from the running stack and judge it against
                    docs/security/audit-events.md: the order, the trace ids, the fields and their
                    values, and the absence of credentials.
Interacts With:    src/api/audit_trail.py (through `docker compose exec`), src/common/audit.py,
                    src/worker/guardrail.py, docs/security/audit-events.md,
                    tests/contract/test_output_audit.py, tests/security/interaction.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.3
Concepts:          Reconstructing one interaction, evidence without credentials, closed field sets
Tools:             Python 3.12, Docker Compose

The rules here are stated once over plain dictionaries (the shape ``AuditRecord.as_dict``
returns and ``poe audit-trail --json`` prints), so the live rows, which read the trail from
the container, and the in-process rows, which read it from the harness's memory store,
judge the same thing the same way.

Four rules, each a function returning findings:

- ``sequence_findings``: the four worker events in their order, then only summary reads,
  exactly as many as the trusted harness made;
- ``field_findings``: every worker event carries only the fields the event list permits,
  every field it must carry, and scalars only (no nested object or list can smuggle the
  answer's text in); a summary read carries its subject and role as strings. The
  permitted set of a summary read is judged by ``read_field_findings``, which the
  credential row applies, so a leaked header is classified by that one row;
- ``value_findings``: the fields equal what the trusted harness knows independently: the
  reading id it submitted, the provider's name, the digest and length of the raw answer it
  replayed through the real emulator, the decision and reason code the real guardrail
  gives that answer, and the state and summary the database holds;
- ``trace_findings``: every record carries a usable trace id; the worker's events carry
  exactly the submitting request's trace id, and each summary read exactly its own
  request's, all distinct;
- ``credential_findings``: no record, rendered whole, contains the token, an
  ``Authorization`` header, or a supplied credential value.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from common.audit import WORKER_SEQUENCE, AuditEvent, AuditRecord, answer_digest
from tests.security.live_record import COMPOSE, StoredRecordError
from worker.guardrail import RejectedSummary, validate_summary

TASK_ROOT = Path(__file__).resolve().parents[2]
TRAIL_TIMEOUT_SECONDS = 60
_TRACE_ID = re.compile(r"^[0-9a-f]{32}$")
_IDENTITY = re.compile(r"^[A-Za-z0-9_.:-]{1,120}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
# The fields each event's `details` may carry, exactly as the table in
# docs/security/audit-events.md lists them (a unit test keeps the two in step). A key
# outside its event's tuple is a finding; so is a value that is not a scalar.
PERMITTED_FIELDS: dict[str, tuple[str, ...]] = {
    AuditEvent.PROCESSING_REQUESTED.value: ("reading_id", "delivery_count"),
    AuditEvent.MODEL_RESPONDED.value: ("provider", "answer_digest", "answer_length"),
    AuditEvent.OUTPUT_VALIDATED.value: ("handling_class", "next_step"),
    AuditEvent.OUTPUT_REJECTED.value: ("reason_code",),
    AuditEvent.OUTCOME_STORED.value: ("state", "summary"),
    AuditEvent.SUMMARY_READ.value: ("subject", "role"),
}
# The fields each event must carry: every permitted field whose value the rows compare.
# `delivery_count` is permitted and, when present, a positive integer, but the delivery
# number is the queue's and not compared.
REQUIRED_FIELDS: dict[str, tuple[str, ...]] = {
    AuditEvent.PROCESSING_REQUESTED.value: ("reading_id",),
    AuditEvent.MODEL_RESPONDED.value: ("provider", "answer_digest", "answer_length"),
    AuditEvent.OUTPUT_VALIDATED.value: ("handling_class", "next_step"),
    AuditEvent.OUTPUT_REJECTED.value: ("reason_code",),
    AuditEvent.OUTCOME_STORED.value: ("state", "summary"),
    AuditEvent.SUMMARY_READ.value: ("subject", "role"),
}
WORKER_EVENTS: frozenset[str] = frozenset().union(*WORKER_SEQUENCE)
SCALAR_TYPES = (str, int, float, bool, type(None))


@dataclass(frozen=True)
class ExpectedInteraction:
    """What the trusted harness knows about one interaction without reading the trail.

    ``answer_text`` is the provider's raw answer as the harness replayed it through the
    real emulator for the same request; the real guardrail's verdict on it is what the
    validation event must report. ``state`` and ``summary`` are what the record holds,
    read through the database (live) or the memory store (in-process). ``subject`` and
    ``role`` are the principal the trusted read was made as.
    """

    exception_id: str
    reading_id: str
    provider: str
    answer_text: str
    state: str
    summary: str | None
    subject: str
    role: str


def fetch_trail(exception_id: str, root: Path = TASK_ROOT) -> list[dict[str, Any]]:
    """Return one exception's audit records from the running stack, as ``poe audit-trail`` does.

    The command runs ``python -m api.audit_trail --json`` inside the ``api`` container,
    where the database is reachable; the host never opens a database port.
    """
    if not _IDENTITY.match(exception_id):
        raise StoredRecordError(f"refusing to read the trail of an unexpected id {exception_id!r}")
    try:
        result = subprocess.run(
            [
                *COMPOSE,
                "exec",
                "-T",
                "api",
                "python",
                "-m",
                "api.audit_trail",
                "--json",
                exception_id,
            ],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=TRAIL_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise StoredRecordError(f"the audit trail could not be read: {exc}") from exc
    if result.returncode != 0:
        raise StoredRecordError(
            f"the audit trail command failed (exit {result.returncode}): {result.stderr.strip()}"
        )
    records: list[dict[str, Any]] = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        try:
            loaded = json.loads(line)
        except ValueError as exc:
            raise StoredRecordError(f"unreadable audit record {line!r}") from exc
        if isinstance(loaded, dict):
            records.append(loaded)
    return records


def as_dicts(records: Iterable[AuditRecord]) -> list[dict[str, Any]]:
    """Return harness records in the same shape the running stack prints."""
    return [record.as_dict() for record in records]


def events_of(records: Sequence[dict[str, Any]]) -> list[str]:
    """Return the event names, in order."""
    return [str(record.get("event", "")) for record in records]


def details_of(record: dict[str, Any]) -> dict[str, Any]:
    """Return one record's details as a dictionary, whatever shape it came in."""
    details = record.get("details")
    return dict(details) if isinstance(details, dict) else {}


def _label(record: dict[str, Any]) -> str:
    """Return the event name with the store's id, for a finding."""
    return f"{record.get('event', '')} (audit_id {record.get('audit_id')})"


# --- Rule 1: the sequence ------------------------------------------------------------------


def sequence_findings(records: Sequence[dict[str, Any]], *, reads: int) -> list[str]:
    """Return why the trail is not the four worker events in order followed by ``reads`` reads."""
    events = events_of(records)
    findings: list[str] = []
    for position, allowed in enumerate(WORKER_SEQUENCE):
        if position >= len(events):
            findings.append(
                f"event {position + 1} is missing: expected {' or '.join(sorted(allowed))}"
            )
            continue
        if events[position] not in allowed:
            findings.append(
                f"event {position + 1} is {events[position]!r}: expected "
                f"{' or '.join(sorted(allowed))}"
            )
    tail = events[len(WORKER_SEQUENCE) :]
    unexpected = [name for name in tail if name != AuditEvent.SUMMARY_READ.value]
    if unexpected:
        findings.append(
            f"after the worker's events only summary_read may follow; found {unexpected}"
        )
    read_count = tail.count(AuditEvent.SUMMARY_READ.value)
    if read_count != reads:
        findings.append(f"expected {reads} summary_read event(s), found {read_count}")
    if len({str(record.get("exception_id", "")) for record in records}) > 1:
        findings.append("the records name more than one exception id")
    return findings


# --- Rule 2: the fields --------------------------------------------------------------------


def _key_findings(record: dict[str, Any]) -> list[str]:
    """Return the permitted-set and scalar findings for one record of any event."""
    event = str(record.get("event", ""))
    details = details_of(record)
    permitted = PERMITTED_FIELDS.get(event)
    if permitted is None:
        return [f"{_label(record)} is not an event the event list names"]
    findings: list[str] = []
    for name in REQUIRED_FIELDS.get(event, ()):
        if name not in details:
            findings.append(f"{event} lacks the field {name!r}")
    for name, value in details.items():
        if name not in permitted:
            findings.append(
                f"{event} carries the field {name!r}, which the event list does not permit "
                f"(permitted: {', '.join(permitted)})"
            )
        if not isinstance(value, SCALAR_TYPES):
            findings.append(
                f"{event}'s field {name!r} is a {type(value).__name__}, not a scalar: the "
                "event list permits no nested object or list"
            )
    return findings


def field_findings(records: Sequence[dict[str, Any]]) -> list[str]:
    """Return why a worker event carries a field it may not, lacks one it must, or nests a value.

    A summary read is held to its required fields only here (``subject`` and ``role`` as
    strings); its permitted set is ``read_field_findings``' rule, which the credential row
    applies, so that a request header leaked into the read is classified by that one row.
    """
    findings: list[str] = []
    for record in records:
        event = str(record.get("event", ""))
        details = details_of(record)
        if event == AuditEvent.SUMMARY_READ.value:
            for name in REQUIRED_FIELDS[event]:
                if not isinstance(details.get(name), str) or not details.get(name):
                    findings.append(f"summary_read's field {name!r} is not a non-empty string")
            continue
        findings.extend(_key_findings(record))
        if event == AuditEvent.MODEL_RESPONDED.value:
            digest = details.get("answer_digest")
            length = details.get("answer_length")
            if not (isinstance(digest, str) and _DIGEST.match(digest)):
                findings.append("model_responded's answer_digest is not a SHA-256 hex digest")
            if isinstance(length, bool) or not isinstance(length, int) or length <= 0:
                findings.append("model_responded's answer_length is not a positive integer")
        if event == AuditEvent.PROCESSING_REQUESTED.value and "delivery_count" in details:
            count = details["delivery_count"]
            if isinstance(count, bool) or not isinstance(count, int) or count < 1:
                findings.append("processing_requested's delivery_count is not a positive integer")
    return findings


def read_field_findings(records: Sequence[dict[str, Any]]) -> list[str]:
    """Return why a summary read carries anything but its subject and role, as scalars.

    Applied by the credential row: a request header, the token, or any other field of the
    request in the read event is a credential finding, not a sequence or field finding.
    """
    return [
        finding
        for record in records
        if str(record.get("event", "")) == AuditEvent.SUMMARY_READ.value
        for finding in _key_findings(record)
    ]


# --- Rule 3: the values --------------------------------------------------------------------


def value_findings(records: Sequence[dict[str, Any]], expected: ExpectedInteraction) -> list[str]:
    """Return every field whose value is not what the trusted harness knows independently.

    The decision is recomputed by the real guardrail over the replayed answer, so the
    validation event must be the one that verdict produces and carry its values; the
    stored outcome must be what the record holds; the model-response event must digest
    exactly the replayed answer.
    """
    verdict = validate_summary(expected.answer_text)
    if isinstance(verdict, RejectedSummary):
        decision = AuditEvent.OUTPUT_REJECTED.value
        decided: dict[str, object] = {"reason_code": verdict.code}
    else:
        decision = AuditEvent.OUTPUT_VALIDATED.value
        decided = {"handling_class": verdict.handling_class, "next_step": verdict.next_step}
    wanted: dict[str, dict[str, object]] = {
        AuditEvent.PROCESSING_REQUESTED.value: {"reading_id": expected.reading_id},
        AuditEvent.MODEL_RESPONDED.value: {
            "provider": expected.provider,
            "answer_digest": answer_digest(expected.answer_text),
            "answer_length": len(expected.answer_text),
        },
        decision: decided,
        AuditEvent.OUTCOME_STORED.value: {"state": expected.state, "summary": expected.summary},
        AuditEvent.SUMMARY_READ.value: {"subject": expected.subject, "role": expected.role},
    }
    findings: list[str] = []
    for record in records:
        event = str(record.get("event", ""))
        if str(record.get("exception_id", "")) != expected.exception_id:
            findings.append(f"{_label(record)} names {record.get('exception_id')!r}")
        if event in (AuditEvent.OUTPUT_VALIDATED.value, AuditEvent.OUTPUT_REJECTED.value):
            if event != decision:
                findings.append(
                    f"the validation event is {event!r}, but the guardrail's verdict on this "
                    f"answer is {decision!r}"
                )
                continue
        for name, value in wanted.get(event, {}).items():
            details = details_of(record)
            if name in details and details[name] != value:
                findings.append(
                    f"{event}'s field {name!r} is {details[name]!r}; the harness expected {value!r}"
                )
    return findings


# --- Rule 4: the trace ids -----------------------------------------------------------------


def _usable_trace_id(value: object) -> bool:
    """Return whether a value is a 32-hex, non-zero trace id."""
    return isinstance(value, str) and bool(_TRACE_ID.match(value)) and set(value) != {"0"}


def trace_findings(
    records: Sequence[dict[str, Any]], *, submission: str, reads: Sequence[str]
) -> list[str]:
    """Return why the trace ids are not exactly the requests' the trusted harness made.

    Every record carries a usable trace id; each worker event carries ``submission``, the
    trace id the harness sent with the reading (the worker continues the intake request's
    trace through the queue); the summary reads carry ``reads`` in order, one per read the
    harness made with that trace id; and no two of these ids coincide.
    """
    findings: list[str] = []
    expected_ids = [submission, *reads]
    if len(set(expected_ids)) != len(expected_ids):
        findings.append("the harness's own trace ids are not distinct; the check cannot judge")
        return findings
    read_ids: list[str] = []
    for record in records:
        event = str(record.get("event", ""))
        trace_id = record.get("trace_id")
        if not _usable_trace_id(trace_id):
            findings.append(f"{event} carries no usable trace id ({trace_id!r})")
            continue
        if event in WORKER_EVENTS and trace_id != submission:
            findings.append(
                f"{event} carries trace id {trace_id}, not the submitting request's {submission}"
            )
        elif event == AuditEvent.SUMMARY_READ.value:
            read_ids.append(str(trace_id))
    if read_ids != list(reads):
        findings.append(
            f"the summary reads carry trace ids {read_ids}; the reading requests were {list(reads)}"
        )
    if len(set(read_ids)) != len(read_ids):
        findings.append("two summary reads carry one trace id")
    if submission in read_ids:
        findings.append("a summary_read carries the worker's trace id, not its own request's")
    return findings


# --- Rule 5: no credentials ----------------------------------------------------------------


def credential_findings(
    records: Sequence[dict[str, Any]], *, token: str, secrets: Sequence[str]
) -> list[str]:
    """Return every record that contains the token, an Authorization header, or a secret value.

    Each record is rendered whole, keys and values, so a credential under any field name
    is found; the header name is matched in any letter case.
    """
    findings: list[str] = []
    for record in records:
        rendered = json.dumps(record, sort_keys=True, default=str)
        label = _label(record)
        if token and token in rendered:
            findings.append(f"{label} contains the dispatcher-valid token")
        if "authorization" in rendered.lower():
            findings.append(f"{label} contains an Authorization header")
        for secret in secrets:
            if secret and secret in rendered:
                findings.append(f"{label} contains a supplied credential value")
    return findings
