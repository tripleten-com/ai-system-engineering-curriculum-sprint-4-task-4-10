"""Coldline.

===================

File:              tests/security/attack_scenario.py
Component:         Security tooling — Combined attack procedure
Purpose:           Send one combined attack (a handling note with personal details, an answer the
                    emulator manipulates, a summary read with an unauthorized token) through the
                    request, token, audit and evidence interfaces of the running stack, and
                    record what each supplied control did, stage by stage, with no personal
                    detail and no credential in the record.
Interacts With:    tests/security/attack_dev.py, tests/contract/held_out_review.py,
                    tests/fixtures/attacks/development.json, the live-record, trail and
                    PII-scan helpers in tests/security/, docs/governance/decision-policy.md
Sprint/Task:       Sprint 4 — Project 4 / Task 4.6
Concepts:          One procedure for the development and the held-out scenario, stage outcomes
                    the decision policy reads, evidence by label
Tools:             Python 3.12, httpx, Docker Compose

One procedure serves two scenarios. ``poe attack-dev`` runs it with the supplied
development scenario and writes every stage to ``evidence/attack-dev.json``; the protected
held-out check runs it with a scenario the student never sees and compares each stage with
the expectation the scenario carries. A scenario names one unauthorized token fixture, one
of the emulator's refused answers, and one handling note with its marked personal values.
The procedure:

1. submits one reading carrying the note and the response selector through the open intake
   (the request interface) and waits for the finished record through the database;
2. ``token_check``: reads the summary with the unauthorized fixture (the token interface)
   and requires the access policy's status, a body that is the access rule's refusal and
   nothing else (one ``detail`` text; any other key, a record column among them, or any
   other form fails the stage), and no ``summary_read`` event added to the trail;
3. reads the finished record once as the dispatcher, so the trail holds exactly one read;
4. ``output_schema``: requires the refused answer to have ended ``NEEDS_REVIEW`` with the
   output policy's fixed message and none of the answer's text in the record;
5. ``redactor``: reads the four locations ``poe pii-scan`` reads (the evidence interface)
   and searches them for the note's marked values; a value the supplied redactor itself
   leaves in the note's text that reached a location is a documented limit of the control
   (``limited``), a value the redactor replaces that reached one anyway is a failure;
6. ``audit_trail``: requires the four worker events in order, the one dispatcher read, the
   permitted fields, the right trace ids, and no credential in any record (the audit
   interface).

Each stage records what was sent, what the control did, one outcome (``held``, ``limited``
or ``failed``, the vocabulary ``docs/governance/decision-policy.md`` reads), the exception
id and, where the stage produced audit events, their ids. Marked values appear as labels
(``A-01 phone``), never as text; no token and no key is written. Every diagnostic a stage
derives from the running stack is bounded to a closed list before it is recorded (a reason
code from the guardrail's list, a record state, an audit event name, a stored-record column
name, an HTTP status), and anything else is written as the fixed word ``unrecognized``; the
trail helpers' findings, whose text repeats record values, are recorded as counts; the
exception id itself is accepted only in the shape the API mints (``EXCEPTION_ID``), and a
run whose intake returned anything else is refused before the id is used. So a value a
defective control let into a record, a personal detail or a credential, can reach neither
the evidence file nor the printed summary. The interfaces are one protocol
(``AttackInterfaces``): ``LiveInterfaces`` reaches the running stack, and the dry run
replaces it with an in-memory stand-in, so the mechanism is provable without the stack.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import httpx

from adapters.model.deterministic import (
    PLANTED_FIELD,
    PLANTED_NEXT_STEP,
    PLANTED_VALUE,
    REJECTED_RESPONSES,
)
from common.audit import AuditEvent
from common.redactor import KINDS, REDACTOR_VERSION, redact
from domain.contracts import ExceptionRecord
from tests.security import live_record, pii, pii_scan, trail
from tests.security.fixtures import EXPECTED_STATUS, REFUSED, bearer_headers, token
from worker.guardrail import REASON_CODES, REVIEW_MESSAGE

TASK_ROOT = Path(__file__).resolve().parents[2]
# The four stages, in the order the procedure runs and records them.
STAGES: tuple[str, ...] = ("token_check", "output_schema", "redactor", "audit_trail")
TOKEN_CHECK, OUTPUT_SCHEMA, REDACTOR, AUDIT_TRAIL = STAGES
# The outcomes a stage records; docs/governance/decision-policy.md reads these words.
OUTCOMES: tuple[str, ...] = ("held", "limited", "failed")
HELD, LIMITED, FAILED = OUTCOMES
# The one token the summary read accepts; the procedure's own read is made with it.
DISPATCHER = "dispatcher-valid"
ROUTE = "/api/v1/exceptions/{exception_id}"
REQUIRED_KEYS = frozenset({"scenario_id", "token_fixture", "response", "note"})
OPTIONAL_KEYS = frozenset({"expected"})
NOTE_KEYS = frozenset({"id", "text", "pii"})
EXPECTED_KEYS = frozenset({"outcome", "result"})
_SCENARIO_ID = re.compile(r"^[a-z][a-z0-9-]{2,40}$")
_NOTE_ID = re.compile(r"^[A-Z]-\d{2}$")
# The exception identities the API mints (`src/domain/exceptions.py`): `exc-` and one UUID.
# An id the intake returns is checked against this before it is used in a query, a trail
# read or a location read and before it is written to the evidence file or printed, so a
# defective stack (or a stand-in) that returns anything else, a credential-shaped value
# among the possibilities, puts nothing of it anywhere: the run is refused instead.
EXCEPTION_ID = re.compile(r"^exc-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
# Text of the emulator's answers that must reach no field of a refused record.
MODEL_TEXT: tuple[str, ...] = (
    "Synthetic shipment",
    "thermal_excursion",
    "operational_review",
    PLANTED_FIELD,
    PLANTED_VALUE,
    PLANTED_NEXT_STEP,
    '"summary"',
)
_OUTPUT_EVENTS = frozenset(
    {
        AuditEvent.OUTPUT_REJECTED.value,
        AuditEvent.OUTPUT_VALIDATED.value,
        AuditEvent.OUTCOME_STORED.value,
    }
)
_FINDING_KEYS = ("sequence_findings", "field_findings", "trace_findings", "credential_findings")
# The bound on every runtime-derived diagnostic: the closed lists a recorded value must come
# from, and the one word written in place of any other value. Nothing read from a record, a
# trail or a response is serialized verbatim.
UNRECOGNIZED = "unrecognized"
KNOWN_STATES: frozenset[str] = frozenset(live_record.FINISHED)
KNOWN_EVENTS: frozenset[str] = frozenset(event.value for event in AuditEvent)
KNOWN_RECORD_FIELDS: frozenset[str] = frozenset(live_record.RECORD_COLUMNS)
KNOWN_REASON_CODES: frozenset[str] = frozenset(REASON_CODES)
# The access rule's refusal (`src/api/security/access.py`, rendered by FastAPI's
# HTTPException): one JSON object whose only key is `detail`, holding the reason as text.
# A refused read's body is held to that shape; a body with any other key or of any other
# form returned something a refusal does not, whatever the status says.
REFUSAL_FIELD = "detail"
# The names a record-bearing response can carry (the API's record model and the stored
# columns), the bound for naming a field that came back beside or instead of a refusal.
KNOWN_RESPONSE_FIELDS: frozenset[str] = (
    frozenset(ExceptionRecord.model_fields) | KNOWN_RECORD_FIELDS
)


def bounded(value: object, allowed: frozenset[str]) -> str:
    """Return a runtime value when it is one of a closed list, else the fixed diagnostic."""
    return value if isinstance(value, str) and value in allowed else UNRECOGNIZED


def bounded_names(values: Iterable[object], allowed: frozenset[str]) -> list[str]:
    """Return the sorted, de-duplicated bound of a list of runtime names."""
    return sorted({bounded(value, allowed) for value in values})


def bounded_status(value: object) -> int | str:
    """Return an HTTP status when it is one, else the fixed diagnostic."""
    if isinstance(value, bool) or not isinstance(value, int) or not 100 <= value <= 599:
        return UNRECOGNIZED
    return value


def bounded_reason(value: object) -> str | None:
    """Return the guardrail's reason code a stored reason starts with, None, or the diagnostic.

    A stored reason is ``<code>`` or ``<code>:<field>`` (``worker.guardrail``); only the
    code is recorded, and only when it is in the guardrail's list. A record with no reason
    (an accepted answer) records None.
    """
    if value is None:
        return None
    code = value.split(":")[0] if isinstance(value, str) else None
    return bounded(code, KNOWN_REASON_CODES)


def refusal_body(text: str) -> tuple[bool, list[str]]:
    """Return whether a response body is the access rule's refusal, and the fields beyond it.

    The refusal is one JSON object whose only key is ``REFUSAL_FIELD`` with text in it.
    Anything else is not a refusal: a body that is not a JSON object (recorded as one
    ``unrecognized`` field), a ``detail`` that is not text, or any further key, whose
    names are recorded bounded to ``KNOWN_RESPONSE_FIELDS``, so a record column that came
    back is named and anything else is ``unrecognized``. The detail's text is never
    recorded.
    """
    try:
        document = json.loads(text)
    except ValueError:
        return False, [UNRECOGNIZED]
    if not isinstance(document, dict):
        return False, [UNRECOGNIZED]
    beyond = bounded_names((key for key in document if key != REFUSAL_FIELD), KNOWN_RESPONSE_FIELDS)
    return isinstance(document.get(REFUSAL_FIELD), str) and not beyond, beyond


def holds_record(text: str, exception_id: str) -> bool:
    """Return whether a response body is the given exception's record: a JSON object naming it."""
    try:
        document = json.loads(text)
    except ValueError:
        return False
    return isinstance(document, dict) and document.get("exception_id") == exception_id


class ScenarioError(Exception):
    """Report that the scenario is unusable or the run could not be made, without detail.

    Distinct from a stage outcome on purpose: a malformed scenario, an intake that did not
    accept the reading, a stack that never finished the record, or a location that could
    not be read is a problem on this side, not a result about the controls. The message
    names the step, never the scenario's content or an API response.
    """


def checked_exception_id(value: object) -> str:
    """Return the exception id the intake returned when it has the API's shape; else refuse.

    Validated before the id is used or serialized (`EXCEPTION_ID`): the message names
    the step and never the value, so a stack that returned a credential, a note or an
    error text in the id's place leaks nothing through the evidence file or the summary.
    """
    if not isinstance(value, str) or not EXCEPTION_ID.match(value):
        raise ScenarioError("the intake returned no usable exception id")
    return value


@dataclass(frozen=True)
class AttackNote:
    """One handling note an attack sends, with the personal values its scenario marks."""

    note_id: str
    text: str
    marked: tuple[pii.MarkedValue, ...]


@dataclass(frozen=True)
class AttackScenario:
    """One combined attack: the fixture, the refused answer, the note, and what to expect."""

    scenario_id: str
    token_fixture: str
    response: str
    note: AttackNote
    expected: dict[str, dict[str, Any]] | None


@dataclass(frozen=True)
class StageResult:
    """What one stage sent, what the control did, and the outcome the policy reads."""

    stage: str
    sent: dict[str, Any]
    result: dict[str, Any]
    outcome: str
    exception_id: str
    audit_event_ids: tuple[int, ...]

    def as_dict(self) -> dict[str, Any]:
        """Return the stage as plain JSON-compatible values."""
        return {
            "stage": self.stage,
            "sent": dict(self.sent),
            "result": dict(self.result),
            "outcome": self.outcome,
            "exception_id": self.exception_id,
            "audit_event_ids": list(self.audit_event_ids),
        }


@dataclass(frozen=True)
class AttackResult:
    """The four stages of one run, in order, with the run's identifiers."""

    scenario_id: str
    exception_id: str
    trace_id: str
    stages: tuple[StageResult, ...]

    def stage(self, name: str) -> StageResult:
        """Return one stage by its name."""
        for stage in self.stages:
            if stage.stage == name:
                return stage
        raise KeyError(name)

    def as_document(self) -> dict[str, Any]:
        """Return the run as the evidence file's JSON document."""
        return {
            "scenario_id": self.scenario_id,
            "exception_id": self.exception_id,
            "trace_id": self.trace_id,
            "stage_order": list(STAGES),
            "stages": {stage.stage: stage.as_dict() for stage in self.stages},
        }


class AttackInterfaces(Protocol):
    """The six interfaces the procedure reaches: the live stack, or an in-memory stand-in."""

    def submit(self, reading: dict[str, Any], trace_id: str) -> str:
        """Post one reading in the given trace; return its exception id."""
        ...

    def wait_finished(self, exception_id: str) -> str:
        """Block until the record is finished; return its state."""
        ...

    def read_summary(self, exception_id: str, fixture: str, trace_id: str) -> tuple[int, str]:
        """Read the summary with one fixture; return the status and the body's text."""
        ...

    def stored_record(self, exception_id: str) -> dict[str, Any] | None:
        """Return the record's output fields as the database holds them."""
        ...

    def locations(self, exception_id: str) -> dict[str, str | None]:
        """Return the four locations' text, as `poe pii-scan` reads them."""
        ...

    def trail(self, exception_id: str) -> list[dict[str, Any]]:
        """Return the exception's audit records, oldest first."""
        ...

    def token(self, fixture: str) -> str:
        """Return one fixture's compact token, for the credential search."""
        ...


# --- The scenario ---------------------------------------------------------------------------


def parse_scenario(document: object, *, require_expected: bool) -> AttackScenario:
    """Return the scenario a JSON document describes, or refuse it.

    The shape is checked strictly and up front: the four keys (and ``expected`` when the
    caller requires it), a refused token fixture, a refused response, a note with an id,
    text and at least one marked value its text holds, and expectations naming known
    stages and outcomes. A scenario that fails here grades nothing.
    """
    if not isinstance(document, dict):
        raise ScenarioError("invalid attack scenario")
    keys = set(document)
    if not REQUIRED_KEYS <= keys or not keys <= REQUIRED_KEYS | OPTIONAL_KEYS:
        raise ScenarioError("invalid attack scenario")
    if require_expected and "expected" not in keys:
        raise ScenarioError("invalid attack scenario")
    scenario_id = document["scenario_id"]
    fixture = document["token_fixture"]
    response = document["response"]
    if not isinstance(scenario_id, str) or not _SCENARIO_ID.match(scenario_id):
        raise ScenarioError("invalid attack scenario")
    if fixture not in REFUSED or response not in REJECTED_RESPONSES:
        raise ScenarioError("invalid attack scenario")
    note = _parse_note(document["note"])
    expected = _parse_expected(document["expected"]) if "expected" in keys else None
    return AttackScenario(
        scenario_id=scenario_id,
        token_fixture=str(fixture),
        response=str(response),
        note=note,
        expected=expected,
    )


def _parse_note(document: object) -> AttackNote:
    """Return the note a scenario carries, with its marked values labelled by kind."""
    if not isinstance(document, dict) or set(document) != NOTE_KEYS:
        raise ScenarioError("invalid attack scenario")
    note_id, text, marked = document["id"], document["text"], document["pii"]
    if not isinstance(note_id, str) or not _NOTE_ID.match(note_id):
        raise ScenarioError("invalid attack scenario")
    if not isinstance(text, str) or not text.strip():
        raise ScenarioError("invalid attack scenario")
    if not isinstance(marked, list) or not marked:
        raise ScenarioError("invalid attack scenario")
    kinds: list[str] = []
    texts: list[str] = []
    for item in marked:
        kind = item.get("kind") if isinstance(item, dict) else None
        value = item.get("value") if isinstance(item, dict) else None
        if kind not in KINDS or not isinstance(value, str) or not value or value not in text:
            raise ScenarioError("invalid attack scenario")
        kinds.append(str(kind))
        texts.append(value)
    # A kind that repeats gets a position in its label, so two values never share one.
    values: list[pii.MarkedValue] = []
    seen: dict[str, int] = {}
    for kind, value in zip(kinds, texts, strict=True):
        seen[kind] = seen.get(kind, 0) + 1
        label = f"{note_id} {kind}"
        if kinds.count(kind) > 1:
            label = f"{label} {seen[kind]}"
        values.append(pii.MarkedValue(label, kind, value))
    return AttackNote(note_id=note_id, text=text, marked=tuple(values))


def _parse_expected(document: object) -> dict[str, dict[str, Any]]:
    """Return the per-stage expectations, or refuse them."""
    if not isinstance(document, dict) or not document:
        raise ScenarioError("invalid attack scenario")
    expected: dict[str, dict[str, Any]] = {}
    for stage, wanted in document.items():
        if stage not in STAGES or not isinstance(wanted, dict):
            raise ScenarioError("invalid attack scenario")
        if not set(wanted) <= EXPECTED_KEYS or wanted.get("outcome") not in OUTCOMES:
            raise ScenarioError("invalid attack scenario")
        result = wanted.get("result", {})
        if not isinstance(result, dict) or not all(isinstance(key, str) for key in result):
            raise ScenarioError("invalid attack scenario")
        expected[str(stage)] = {"outcome": str(wanted["outcome"]), "result": dict(result)}
    return expected


def load_scenario_text(text: str, *, require_expected: bool) -> AttackScenario:
    """Parse a scenario from its JSON text; a text that is not JSON is refused the same way."""
    try:
        document = json.loads(text)
    except ValueError as exc:
        raise ScenarioError("invalid attack scenario") from exc
    return parse_scenario(document, require_expected=require_expected)


# --- The live interfaces --------------------------------------------------------------------


class LiveInterfaces:
    """The running stack behind the six interfaces: the API on the host, Compose for the rest."""

    def __init__(self, client: httpx.Client, root: Path = TASK_ROOT) -> None:
        """Bind the procedure to one API client and one Task root for the Compose commands."""
        self._client = client
        self._root = root

    def submit(self, reading: dict[str, Any], trace_id: str) -> str:
        """Post the reading through the open intake in the given trace."""
        try:
            accepted = self._client.post(
                "/api/v1/readings", json=reading, headers=live_record.traceparent(trace_id)
            )
        except httpx.HTTPError as exc:
            raise ScenarioError("the intake did not answer") from exc
        if accepted.status_code != 202:
            raise ScenarioError("the intake did not accept the reading")
        try:
            body = accepted.json()
        except ValueError as exc:
            raise ScenarioError("the intake answered in an unexpected form") from exc
        return checked_exception_id(body.get("exception_id") if isinstance(body, dict) else None)

    def wait_finished(self, exception_id: str) -> str:
        """Wait for the record through the database, as the trusted rows do."""
        try:
            return live_record.wait_for_finished(exception_id, root=self._root)
        except live_record.StoredRecordError as exc:
            raise ScenarioError("the record did not finish") from exc

    def read_summary(self, exception_id: str, fixture: str, trace_id: str) -> tuple[int, str]:
        """Read the summary with one fixture; return the status and the body as the API sent it."""
        try:
            response = self._client.get(
                ROUTE.format(exception_id=exception_id),
                headers={**bearer_headers(fixture), **live_record.traceparent(trace_id)},
            )
        except httpx.HTTPError as exc:
            raise ScenarioError("the summary read did not answer") from exc
        return response.status_code, response.text

    def stored_record(self, exception_id: str) -> dict[str, Any] | None:
        """Return the record's output fields from the database."""
        try:
            return live_record.stored_record(exception_id, self._root)
        except live_record.StoredRecordError as exc:
            raise ScenarioError("the stored record could not be read") from exc

    def locations(self, exception_id: str) -> dict[str, str | None]:
        """Return the four locations as `poe pii-scan` reads them."""
        try:
            return pii_scan.live_locations(exception_id, self._root)
        except live_record.StoredRecordError as exc:
            raise ScenarioError("the evidence locations could not be read") from exc

    def trail(self, exception_id: str) -> list[dict[str, Any]]:
        """Return the audit trail as `poe audit-trail --json` prints it."""
        try:
            return trail.fetch_trail(exception_id, self._root)
        except live_record.StoredRecordError as exc:
            raise ScenarioError("the audit trail could not be read") from exc

    def token(self, fixture: str) -> str:
        """Return one fixture's compact token."""
        return token(fixture)


# --- The procedure --------------------------------------------------------------------------


def _summary_reads(records: Sequence[Mapping[str, Any]]) -> int:
    """Return how many summary-read events the trail holds."""
    return sum(1 for record in records if record.get("event") == AuditEvent.SUMMARY_READ.value)


def _event_ids(records: Sequence[Mapping[str, Any]], events: frozenset[str]) -> tuple[int, ...]:
    """Return the store ids of the records whose event is one of ``events``, in trail order."""
    ids: list[int] = []
    for record in records:
        audit_id = record.get("audit_id")
        if (
            record.get("event") in events
            and isinstance(audit_id, int)
            and not isinstance(audit_id, bool)
        ):
            ids.append(audit_id)
    return tuple(ids)


def classify_redaction(
    note: AttackNote, locations: Mapping[str, str | None]
) -> tuple[str, list[dict[str, Any]]]:
    """Return the redactor stage's outcome and one labelled line per marked value.

    Each marked value is searched in the four locations as ``poe pii-scan`` searches them,
    and the supplied redactor is run over the note's text in this process to learn whether
    it replaces that value at all. A value that reached a location although the redactor
    replaces it is a failure of the control (the worker did not apply it where it must);
    a value that reached a location and that the redactor leaves in the note's text is a
    documented limit of the control (``limited``); no value reaching any location is
    ``held``. The lines name labels and locations, never the values.
    """
    redacted_text = redact(note.text)
    found = pii.findings(locations, note.marked)
    lines: list[dict[str, Any]] = []
    reached_any = False
    failed = False
    for item in note.marked:
        reached = [finding.location for finding in found if finding.label == item.label]
        replaces = item.value not in redacted_text
        lines.append(
            {
                "label": item.label,
                "kind": item.kind,
                "redactor_replaces_it": replaces,
                "reached": reached,
            }
        )
        if reached:
            reached_any = True
            if replaces:
                failed = True
    outcome = FAILED if failed else LIMITED if reached_any else HELD
    return outcome, lines


def _token_stage(
    scenario: AttackScenario, interfaces: AttackInterfaces, exception_id: str
) -> tuple[StageResult, str]:
    """Read the summary with the unauthorized fixture and record what the token check did.

    The stage holds when the status is the access policy's for the fixture, the body is
    the access rule's refusal and nothing else (``refusal_body``: a response with the
    expected status that carries a record field, or anything but one ``detail`` text,
    fails the stage), and no ``summary_read`` event was added. Returns the stage and the
    trace id the unauthorized read was made in, so the audit stage can account for a read
    the token check let through instead of failing twice.
    """
    before = _summary_reads(interfaces.trail(exception_id))
    unauthorized_trace = live_record.new_trace_id()
    status, body = interfaces.read_summary(exception_id, scenario.token_fixture, unauthorized_trace)
    refusal, beyond = refusal_body(body)
    added = _summary_reads(interfaces.trail(exception_id)) - before
    expected = EXPECTED_STATUS[scenario.token_fixture]
    held = status == expected and refusal and added == 0
    stage = StageResult(
        stage=TOKEN_CHECK,
        sent={"method": "GET", "route": ROUTE, "token_fixture": scenario.token_fixture},
        result={
            "status": bounded_status(status),
            "expected_status": expected,
            "refusal_body": refusal,
            "fields_beyond_refusal": beyond,
            "summary_read_events_added": added,
        },
        outcome=HELD if held else FAILED,
        exception_id=exception_id,
        # A refused read never reaches the route body and records nothing
        # (docs/security/audit-events.md); the stage lists no event on purpose.
        audit_event_ids=(),
    )
    return stage, unauthorized_trace


def _output_stage(
    scenario: AttackScenario,
    record: Mapping[str, Any],
    records: Sequence[Mapping[str, Any]],
    exception_id: str,
) -> StageResult:
    """Judge the stored record of the refused answer against the output policy.

    The recorded state, reason code and leaking field names are bounded (``bounded``):
    a record a defective control filled with the answer's text, or with anything else,
    yields ``unrecognized`` in the evidence, never the value.
    """
    state = bounded(record.get("state"), KNOWN_STATES)
    summary = record.get("summary")
    code = bounded_reason(record.get("rejection_reason"))
    fixed = summary == REVIEW_MESSAGE
    validated_fields = (
        record.get("handling_class") is not None or record.get("next_step") is not None
    )
    leaked = bounded_names(
        (
            name
            for name, value in record.items()
            if isinstance(value, str)
            and name != "summary"
            and any(text in value for text in MODEL_TEXT)
        ),
        KNOWN_RECORD_FIELDS,
    )
    held = (
        state == live_record.NEEDS_REVIEW
        and fixed
        and code in KNOWN_REASON_CODES
        and not validated_fields
        and not leaked
    )
    return StageResult(
        stage=OUTPUT_SCHEMA,
        sent={"response": scenario.response},
        result={
            "state": state,
            "rejection_reason": code,
            "summary_is_fixed_message": fixed,
            "validated_fields_stored": validated_fields,
            "answer_text_in_record": leaked,
        },
        outcome=HELD if held else FAILED,
        exception_id=exception_id,
        audit_event_ids=_event_ids(records, _OUTPUT_EVENTS),
    )


def _redactor_stage(
    scenario: AttackScenario, locations: Mapping[str, str | None], exception_id: str
) -> StageResult:
    """Search the four locations for the marked values and classify what the redactor did."""
    if pii_scan.unavailable_locations(locations):
        raise ScenarioError("an evidence location could not be read")
    outcome, lines = classify_redaction(scenario.note, locations)
    return StageResult(
        stage=REDACTOR,
        sent={
            "note": scenario.note.note_id,
            "marked_kinds": [item.kind for item in scenario.note.marked],
        },
        result={
            "redactor_version": REDACTOR_VERSION,
            "locations_read": list(pii.LOCATIONS),
            "values": lines,
        },
        outcome=outcome,
        exception_id=exception_id,
        audit_event_ids=(),
    )


def _audit_stage(
    scenario: AttackScenario,
    interfaces: AttackInterfaces,
    records: Sequence[dict[str, Any]],
    *,
    exception_id: str,
    submission_trace: str,
    read_traces: Sequence[str],
) -> StageResult:
    """Judge the trail: the sequence, the fields, the trace ids, and no credential anywhere.

    ``read_traces`` are the trace ids of the reads that returned the record, in order: the
    dispatcher's, and before it the unauthorized read's when the token check let it
    through, so that failure is the token stage's alone and the trail is judged for what
    it must then hold.

    The helpers' findings name record values (an unexpected event, a field, a trace id,
    the record that holds a credential), so the stage records how many findings each rule
    made, never their text; the event names are bounded to the audit event list. The
    records themselves stay readable through `poe audit-trail`.
    """
    sequence = trail.sequence_findings(records, reads=len(read_traces))
    fields = trail.field_findings(records) + trail.read_field_findings(records)
    traces = trail.trace_findings(records, submission=submission_trace, reads=read_traces)
    credentials = trail.credential_findings(
        records,
        token=interfaces.token(DISPATCHER),
        secrets=(interfaces.token(scenario.token_fixture),),
    )
    held = not (sequence or fields or traces or credentials)
    return StageResult(
        stage=AUDIT_TRAIL,
        sent={"summary_reads_made": len(read_traces), "read_as": DISPATCHER},
        result={
            "events": [bounded(event, KNOWN_EVENTS) for event in trail.events_of(records)],
            "summary_reads": _summary_reads(records),
            "sequence_findings": len(sequence),
            "field_findings": len(fields),
            "trace_findings": len(traces),
            "credential_findings": len(credentials),
        },
        outcome=HELD if held else FAILED,
        exception_id=exception_id,
        audit_event_ids=_event_ids(records, frozenset(trail.PERMITTED_FIELDS)),
    )


def run_attack(scenario: AttackScenario, interfaces: AttackInterfaces) -> AttackResult:
    """Send the combined attack through the interfaces and return the four stages.

    Raises ``ScenarioError`` when the run could not be made: the intake refused the
    reading or returned no id of the API's shape (``checked_exception_id``, applied to
    every interface's answer before the id is used), the record never finished (or ended
    ``FAILED``, which means no answer came back for the output control to judge), the
    trusted dispatcher read did not return the record, or a location could not be read.
    None of those is a result about a control.
    """
    reading = live_record.unique_reading(
        response=scenario.response, prefix="attack", note=scenario.note.text
    )
    trace_id = live_record.new_trace_id()
    try:
        exception_id = checked_exception_id(interfaces.submit(reading, trace_id))
        state = interfaces.wait_finished(exception_id)
        if state == live_record.FAILED:
            raise ScenarioError("the record ended FAILED: no answer came back to judge")
        token_stage, unauthorized_trace = _token_stage(scenario, interfaces, exception_id)
        read_trace = live_record.new_trace_id()
        status, body = interfaces.read_summary(exception_id, DISPATCHER, read_trace)
        if status != 200 or not holds_record(body, exception_id):
            raise ScenarioError("the dispatcher read did not return the record")
        record = interfaces.stored_record(exception_id)
        if record is None:
            raise ScenarioError("the record is not in the database")
        records = interfaces.trail(exception_id)
        output_stage = _output_stage(scenario, record, records, exception_id)
        locations = interfaces.locations(exception_id)
        redactor_stage = _redactor_stage(scenario, locations, exception_id)
        read_traces = [read_trace]
        if token_stage.result["summary_read_events_added"]:
            read_traces.insert(0, unauthorized_trace)
        audit_stage = _audit_stage(
            scenario,
            interfaces,
            records,
            exception_id=exception_id,
            submission_trace=trace_id,
            read_traces=tuple(read_traces),
        )
    except httpx.HTTPError as exc:
        raise ScenarioError("the stack did not answer") from exc
    except (KeyError, TypeError, ValueError) as exc:
        raise ScenarioError("the stack answered in an unexpected form") from exc
    return AttackResult(
        scenario_id=scenario.scenario_id,
        exception_id=exception_id,
        trace_id=trace_id,
        stages=(token_stage, output_stage, redactor_stage, audit_stage),
    )


def grade(result: AttackResult, expected: Mapping[str, Mapping[str, Any]]) -> list[str]:
    """Return the stage keys whose recorded value is not the expected one; empty is a pass.

    Each expectation names a stage, its outcome and, optionally, result fields. The
    findings name the stage and the key only, never a value, so they can be logged by a
    caller that must not describe the scenario.
    """
    findings: list[str] = []
    for stage_name, wanted in expected.items():
        try:
            stage = result.stage(stage_name)
        except KeyError:
            findings.append(f"{stage_name}: missing")
            continue
        if stage.outcome != wanted.get("outcome"):
            findings.append(f"{stage_name}: outcome")
        for key, value in dict(wanted.get("result", {})).items():
            if stage.result.get(key) != value:
                findings.append(f"{stage_name}: {key}")
    return findings


def _detail(stage: StageResult) -> str:
    """Render one stage's result for the summary: labels, statuses and counts, no values.

    Every field read here is a scenario-supplied label, a bounded diagnostic or a count,
    so the printed line can carry nothing the stack returned.
    """
    result = stage.result
    if stage.stage == TOKEN_CHECK:
        refusal = "yes" if result["refusal_body"] else "no"
        if result["fields_beyond_refusal"]:
            refusal = f"{refusal} ({', '.join(result['fields_beyond_refusal'])})"
        return (
            f"{stage.sent['token_fixture']} -> {result['status']} (expected "
            f"{result['expected_status']}), refusal body: {refusal}, summary_read "
            f"events added: {result['summary_read_events_added']}"
        )
    if stage.stage == OUTPUT_SCHEMA:
        fixed = "yes" if result["summary_is_fixed_message"] else "no"
        return (
            f"{stage.sent['response']} -> state {result['state']}, reason "
            f"{result['rejection_reason']}, fixed message: {fixed}"
        )
    if stage.stage == REDACTOR:
        reached = [
            f"{line['label']} in {', '.join(line['reached'])}"
            for line in result["values"]
            if line["reached"]
        ]
        where = "; ".join(reached) if reached else "no marked value reached a location"
        marked = ", ".join(stage.sent["marked_kinds"])
        return f"note {stage.sent['note']}, marked {marked}; {where}"
    total = sum(int(result[key]) for key in _FINDING_KEYS)
    return f"events {', '.join(result['events'])}; findings: {total}"


def summary_lines(result: AttackResult) -> list[str]:
    """Render the stage summary a student copies into the pull request: labels and ids only."""
    lines: list[str] = []
    for stage in result.stages:
        ids = ", ".join(str(item) for item in stage.audit_event_ids) or "none"
        lines.append(f"{stage.stage}: {stage.outcome} ({_detail(stage)}); audit event ids: {ids}")
    return lines
