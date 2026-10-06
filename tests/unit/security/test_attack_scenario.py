"""Coldline.

===================

File:              tests/unit/security/test_attack_scenario.py
Component:         Unit tests — Combined attack procedure
Purpose:           Prove the scenario shape is enforced, the redactor stage is classified from
                    what the supplied redactor does, the token stage holds a refusal to the
                    access rule's error shape, the grade compares what the scenario
                    expects, every runtime-derived diagnostic is bounded, the exception id
                    is accepted in the API's shape alone, and the evidence and the summary
                    carry no marked value, no record value and no credential.
Interacts With:    tests/security/attack_scenario.py, tests/security/attack_dev.py,
                    tests/fixtures/attacks/development.json
Sprint/Task:       Sprint 4 — Project 4 / Task 4.6
Concepts:          Evidence by label, deterministic stage outcomes, bounded diagnostics
Tools:             Python 3.12, pytest

Public fixtures demonstrate the harness interfaces and make no statement about the
protected scenario's inputs.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from common.redactor import redact
from tests.security import attack_dev, attack_scenario, pii
from tests.security.attack_scenario import (
    AUDIT_TRAIL,
    FAILED,
    HELD,
    KNOWN_EVENTS,
    KNOWN_REASON_CODES,
    KNOWN_RESPONSE_FIELDS,
    LIMITED,
    OUTPUT_SCHEMA,
    REDACTOR,
    STAGES,
    TOKEN_CHECK,
    UNRECOGNIZED,
    AttackNote,
    AttackResult,
    ScenarioError,
    StageResult,
    bounded,
    bounded_reason,
    bounded_status,
    classify_redaction,
    grade,
    holds_record,
    load_scenario_text,
    parse_scenario,
    refusal_body,
    run_attack,
    summary_lines,
)
from tests.security.fixtures import EXPECTED_STATUS
from worker.guardrail import REVIEW_MESSAGE

TASK_ROOT = Path(__file__).resolve().parents[3]
# A note invented for these tests: the name follows a cue and the number has seven digits,
# so the supplied redactor replaces both.
NOTE = AttackNote(
    note_id="U-01",
    text="Reach Dana Whitfield on 555-0160 before the pallet moves.",
    marked=(
        pii.MarkedValue("U-01 name", "name", "Dana Whitfield"),
        pii.MarkedValue("U-01 phone", "phone", "555-0160"),
    ),
)
# The same values with the name opening the sentence, which the redactor leaves in place.
OPENING_NOTE = AttackNote(
    note_id="U-02",
    text="Dana Whitfield has the keys; reach the desk on 555-0160.",
    marked=(
        pii.MarkedValue("U-02 name", "name", "Dana Whitfield"),
        pii.MarkedValue("U-02 phone", "phone", "555-0160"),
    ),
)
# One refused token fixture (a 401) and one refused answer, for these tests.
SCENARIO: dict[str, Any] = {
    "scenario_id": "unit-test",
    "token_fixture": "wrong-issuer",
    "response": "manipulated",
    "note": {
        "id": "U-01",
        "text": NOTE.text,
        "pii": [{"kind": item.kind, "value": item.value} for item in NOTE.marked],
    },
}
# A credential-shaped value no fixture holds, injected where a defective stack could put one.
SENTINEL = "cpk_unit_sentinel_7f3a9c"
# An exception id in the shape the API mints (`exc-` and one UUID), for the stand-ins.
UNIT_EXCEPTION_ID = "exc-1b4e28ba-2fa1-11d2-883f-0016d3cca427"


def _locations(note: AttackNote, *, raw: bool = False) -> dict[str, str | None]:
    """Return four locations as a worker that redacts (or, raw, does not) would leave them."""
    shown = note.text if raw else redact(note.text)
    return {
        "worker logs": f"reading job handling_note={shown}",
        "model request": f"handling_note: {shown}",
        "audit records": '{"state": "NEEDS_REVIEW"}',
        "stored summary": "Automatic summary withheld.",
    }


def test_the_scenario_shape_is_enforced() -> None:
    """A usable scenario parses; a missing key, accepted fixture or answer, or bad note fails."""
    scenario = parse_scenario(SCENARIO, require_expected=False)
    assert scenario.token_fixture == "wrong-issuer"
    assert scenario.response == "manipulated"
    assert [item.label for item in scenario.note.marked] == ["U-01 name", "U-01 phone"]
    assert scenario.expected is None

    with pytest.raises(ScenarioError):
        parse_scenario(SCENARIO, require_expected=True)
    for broken in (
        {**SCENARIO, "token_fixture": "dispatcher-valid"},
        {**SCENARIO, "response": "pii-echo"},
        {**SCENARIO, "scenario_id": "Bad Id"},
        {**SCENARIO, "note": {**SCENARIO["note"], "id": "u1"}},
        {**SCENARIO, "note": {**SCENARIO["note"], "pii": [{"kind": "address", "value": "x"}]}},
        {**SCENARIO, "expected": {}},
        {**SCENARIO, "expected": {"redactor": {"outcome": HELD, "extra": 1}}},
        [SCENARIO],
    ):
        with pytest.raises(ScenarioError):
            parse_scenario(broken, require_expected=False)
    with pytest.raises(ScenarioError):
        load_scenario_text("{", require_expected=False)


def test_a_repeated_kind_gets_a_position_in_its_label() -> None:
    """Two values of one kind are told apart by position, so no two labels coincide."""
    document = {
        **SCENARIO,
        "note": {
            "id": "U-03",
            "text": "Reach Dana Whitfield on 555-0160 or 555-0161.",
            "pii": [
                {"kind": "name", "value": "Dana Whitfield"},
                {"kind": "phone", "value": "555-0160"},
                {"kind": "phone", "value": "555-0161"},
            ],
        },
    }
    scenario = parse_scenario(document, require_expected=False)
    assert [item.label for item in scenario.note.marked] == [
        "U-03 name",
        "U-03 phone 1",
        "U-03 phone 2",
    ]


def test_the_redactor_stage_is_classified_from_what_the_redactor_does() -> None:
    """Held if nothing reached a location; limited if only unrecognized values did; else failed."""
    outcome, lines = classify_redaction(NOTE, _locations(NOTE))
    assert outcome == HELD
    assert all(line["redactor_replaces_it"] and not line["reached"] for line in lines)

    outcome, lines = classify_redaction(OPENING_NOTE, _locations(OPENING_NOTE))
    assert outcome == LIMITED
    by_label = {line["label"]: line for line in lines}
    assert by_label["U-02 name"]["redactor_replaces_it"] is False
    assert by_label["U-02 name"]["reached"] == ["worker logs", "model request"]
    assert by_label["U-02 phone"]["reached"] == []

    outcome, lines = classify_redaction(NOTE, _locations(NOTE, raw=True))
    assert outcome == FAILED
    assert all(line["reached"] == ["worker logs", "model request"] for line in lines)
    for line in lines:
        assert NOTE.marked[0].value not in json.dumps(line)
        assert NOTE.marked[1].value not in json.dumps(line)


def _result(**outcomes: str) -> AttackResult:
    """Build a result whose stages carry the given outcomes (held by default) and small results."""
    stages = tuple(
        StageResult(
            stage=name,
            sent={},
            result=(
                {"status": 401} if name == TOKEN_CHECK else {"rejection_reason": "unknown_property"}
            ),
            outcome=outcomes.get(name, HELD),
            exception_id=UNIT_EXCEPTION_ID,
            audit_event_ids=(1, 2),
        )
        for name in STAGES
    )
    return AttackResult("unit-test", UNIT_EXCEPTION_ID, "0" * 32, stages)


def test_the_grade_compares_outcomes_and_result_fields_and_names_keys_only() -> None:
    """A pass is an empty finding list; a difference names the stage and the key, never a value."""
    assert grade(_result(), {TOKEN_CHECK: {"outcome": HELD, "result": {"status": 401}}}) == []
    findings = grade(
        _result(redactor=LIMITED),
        {
            TOKEN_CHECK: {"outcome": HELD, "result": {"status": 400}},
            REDACTOR: {"outcome": HELD},
            AUDIT_TRAIL: {"outcome": HELD},
            "secret_check": {"outcome": HELD},
        },
    )
    assert findings == ["token_check: status", "redactor: outcome", "secret_check: missing"]
    assert not any("401" in finding or "400" in finding for finding in findings)


def test_runtime_diagnostics_are_bounded_to_closed_lists() -> None:
    """A value from a closed list is kept; anything else becomes the fixed diagnostic."""
    assert bounded("unknown_property", KNOWN_REASON_CODES) == "unknown_property"
    assert bounded("unknown_property: Dana Whitfield", KNOWN_REASON_CODES) == UNRECOGNIZED
    assert bounded(None, KNOWN_EVENTS) == UNRECOGNIZED
    assert bounded("summary_read", KNOWN_EVENTS) == "summary_read"
    assert bounded_reason(None) is None
    assert bounded_reason("missing_property:summary") == "missing_property"
    assert bounded_reason("weird: Dana Whitfield") == UNRECOGNIZED
    assert bounded_reason(12) == UNRECOGNIZED
    assert bounded_status(401) == 401
    for wrong in (True, 99, 600, "401", None):
        assert bounded_status(wrong) == UNRECOGNIZED


class _InjectingStack:
    """A stand-in whose every runtime-derived value carries a marked value or the sentinel.

    The controls are all defective on purpose: the record's state, reason, an extra
    field, the audit events' names, details and trace ids, and the tokens all carry the
    note's contact name or the credential sentinel, which is what a broken control could
    let into a record. The procedure must record outcomes about it and nothing of it.
    ``exception_id`` is what its intake returns: the API's shape by default, or anything
    a defective intake might return.
    """

    def __init__(self, note: AttackNote, exception_id: Any = UNIT_EXCEPTION_ID) -> None:
        self.note = note
        self.name = note.marked[0].value
        self.exception_id = exception_id
        self.refusal = json.dumps(
            {attack_scenario.REFUSAL_FIELD: f"token rejected: {self.name} {SENTINEL}"}
        )
        self.records: list[dict[str, Any]] = [
            {
                "audit_id": 1,
                "event": f"processing_requested {self.name}",
                "exception_id": exception_id,
                "trace_id": SENTINEL,
                "details": {"reading_id": self.name, "authorization": SENTINEL},
            },
            {
                "audit_id": 2,
                "event": "outcome_stored",
                "exception_id": exception_id,
                "trace_id": "1" * 32,
                "details": {"state": self.name, "summary": SENTINEL},
            },
        ]

    def submit(self, reading: dict[str, Any], trace_id: str) -> str:
        return self.exception_id

    def wait_finished(self, exception_id: str) -> str:
        return "NEEDS_REVIEW"

    def read_summary(self, exception_id: str, fixture: str, trace_id: str) -> tuple[int, str]:
        if fixture == attack_scenario.DISPATCHER:
            record = {"exception_id": self.exception_id, "state": self.name, "summary": SENTINEL}
            return 200, json.dumps(record)
        return EXPECTED_STATUS[fixture], self.refusal

    # What the unauthorized read answers: the access rule's refusal, with the name and the
    # sentinel in its text, unless a test replaces it with a body a defective rule returned.
    refusal = json.dumps({attack_scenario.REFUSAL_FIELD: "token rejected: see note"})

    def stored_record(self, exception_id: str) -> dict[str, Any] | None:
        return {
            "state": f"NEEDS_REVIEW {self.name}",
            "summary": REVIEW_MESSAGE,
            "handling_class": None,
            "next_step": None,
            "rejection_reason": f"unknown_property: {self.name} {SENTINEL}",
            "failure_reason": None,
            SENTINEL: f"Synthetic shipment for {self.name}",
        }

    def locations(self, exception_id: str) -> dict[str, str | None]:
        return _locations(self.note, raw=True)

    def trail(self, exception_id: str) -> list[dict[str, Any]]:
        return [dict(record) for record in self.records]

    def token(self, fixture: str) -> str:
        return f"{SENTINEL}-{fixture}"


def test_the_full_procedure_records_no_personal_value_and_no_credential() -> None:
    """Over a stack that leaks everywhere, the evidence and the summary carry labels and bounds."""
    scenario = parse_scenario(SCENARIO, require_expected=False)
    stack = _InjectingStack(scenario.note)

    result = run_attack(scenario, stack)

    document = attack_dev.evidence_document(result, scenario_file="unit.json")
    rendered = json.dumps(document) + "\n".join(summary_lines(result))
    for item in scenario.note.marked:
        assert item.value not in rendered, item.label
        assert item.label in rendered, item.label
    assert SENTINEL not in rendered
    assert stack.token("x") not in rendered
    output = result.stage(OUTPUT_SCHEMA)
    assert output.outcome == FAILED
    assert output.result["state"] == UNRECOGNIZED
    assert output.result["rejection_reason"] == "unknown_property"
    assert output.result["answer_text_in_record"] == [UNRECOGNIZED]
    audit = result.stage(AUDIT_TRAIL)
    assert audit.outcome == FAILED
    assert audit.result["events"] == [UNRECOGNIZED, "outcome_stored"]
    for key in ("sequence_findings", "field_findings", "trace_findings", "credential_findings"):
        assert isinstance(audit.result[key], int), key
    assert audit.result["credential_findings"] >= 1
    token = result.stage(TOKEN_CHECK)
    assert token.outcome == HELD and token.result["status"] == 401
    assert token.result["refusal_body"] is True and token.result["fields_beyond_refusal"] == []
    assert result.stage(REDACTOR).outcome == FAILED


@pytest.mark.parametrize(
    "body,beyond",
    [
        (json.dumps({"summary": "confidential shipment details"}), ["summary"]),
        (
            json.dumps({"state": "COMPLETED", "handling_class": "thermal_excursion"}),
            ["handling_class", "state"],
        ),
        (
            json.dumps({"exception_id": UNIT_EXCEPTION_ID, "summary": "confidential"}),
            ["exception_id", "summary"],
        ),
        (
            json.dumps({"detail": "token rejected", "summary": "confidential shipment details"}),
            ["summary"],
        ),
        (
            json.dumps({"detail": "token rejected", "note": "confidential shipment details"}),
            [UNRECOGNIZED],
        ),
        (json.dumps({"detail": ["a list, as a validation error renders"]}), []),
        (json.dumps({"detail": None}), []),
        (json.dumps({}), []),
        ("confidential shipment details", [UNRECOGNIZED]),
        ("[]", [UNRECOGNIZED]),
        ("", [UNRECOGNIZED]),
    ],
    ids=[
        "summary-only",
        "state-and-class",
        "record-with-id",
        "detail-and-summary",
        "detail-and-unknown-key",
        "detail-not-text",
        "detail-null",
        "empty-object",
        "plain-text",
        "array",
        "empty-body",
    ],
)
def test_a_refusal_with_the_expected_status_but_not_the_error_shape_fails_the_token_stage(
    body: str, beyond: list[str]
) -> None:
    """The regression round 3 named: a 401 whose body carries a record field is a failure.

    The token stage holds the refusal body to the access rule's error shape (one `detail`
    text and nothing else) instead of searching it for one field name: a response with the
    expected status that returns `summary`, `state`, `handling_class` or anything beyond
    the refusal fails the stage, the fields are recorded bounded (a record column by its
    name, anything else as `unrecognized`), and nothing of the body's content reaches the
    evidence or the summary.
    """
    scenario = parse_scenario(SCENARIO, require_expected=False)
    stack = _InjectingStack(scenario.note)
    stack.refusal = body

    result = run_attack(scenario, stack)

    token = result.stage(TOKEN_CHECK)
    assert token.outcome == FAILED
    assert token.result["status"] == 401 == token.result["expected_status"]
    assert token.result["refusal_body"] is False
    assert token.result["fields_beyond_refusal"] == beyond
    assert token.result["summary_read_events_added"] == 0
    assert all(name in KNOWN_RESPONSE_FIELDS or name == UNRECOGNIZED for name in beyond)
    document = attack_dev.evidence_document(result, scenario_file="unit.json")
    rendered = json.dumps(document) + "\n".join(summary_lines(result))
    for content in ("confidential", "thermal_excursion", "COMPLETED", "validation error"):
        assert content not in rendered, content
    assert "refusal body: no" in "\n".join(summary_lines(result))


def test_the_refusal_body_is_the_access_rules_error_shape_and_nothing_else() -> None:
    """One JSON object, one `detail` text: the shape `src/api/security/access.py` raises."""
    assert refusal_body(json.dumps({"detail": "token rejected: expired"})) == (True, [])
    assert refusal_body(json.dumps({"detail": ""})) == (True, [])
    assert refusal_body(json.dumps({"detail": "x", "summary": "y"})) == (False, ["summary"])
    assert refusal_body("{") == (False, [UNRECOGNIZED])
    assert KNOWN_RESPONSE_FIELDS >= {"exception_id", "state", "summary", "handling_class"}
    assert holds_record(json.dumps({"exception_id": UNIT_EXCEPTION_ID}), UNIT_EXCEPTION_ID)
    assert not holds_record(json.dumps({"exception_id": "exc-other"}), UNIT_EXCEPTION_ID)
    assert not holds_record(json.dumps({"detail": UNIT_EXCEPTION_ID}), UNIT_EXCEPTION_ID)
    assert not holds_record(UNIT_EXCEPTION_ID, UNIT_EXCEPTION_ID)


@pytest.mark.parametrize(
    "returned",
    [SENTINEL, f"exc-{SENTINEL}", "exc-unit", "exc-reading-attack-0123456789abcdef", "", 7],
    ids=["credential", "credential-after-prefix", "word", "reading-id", "empty", "number"],
)
def test_an_exception_id_outside_the_api_shape_is_refused_before_it_is_used(
    returned: Any,
) -> None:
    """An intake answer that is not `exc-<uuid>` ends the run; the value reaches no output.

    The id is the one runtime value a stage serializes verbatim, so it is accepted in the
    API's shape alone (`EXCEPTION_ID`): a credential-shaped value, a note or an error text
    in its place is refused with the fixed message, before any interface is read with it
    and before any evidence or summary line exists to carry it.
    """
    scenario = parse_scenario(SCENARIO, require_expected=False)
    stack = _InjectingStack(scenario.note, exception_id=returned)

    with pytest.raises(ScenarioError) as refused:
        run_attack(scenario, stack)

    assert str(refused.value) == "the intake returned no usable exception id"
    assert str(returned) not in str(refused.value) or returned == ""
    assert attack_scenario.checked_exception_id(UNIT_EXCEPTION_ID) == UNIT_EXCEPTION_ID
    with pytest.raises(ScenarioError):
        attack_scenario.checked_exception_id(UNIT_EXCEPTION_ID.upper())


def test_the_summary_and_the_evidence_carry_labels_and_ids_but_no_value_or_token() -> None:
    """The evidence document and the summary name labels and event ids; no marked value appears."""
    scenario = parse_scenario(SCENARIO, require_expected=False)
    outcome, lines = classify_redaction(scenario.note, _locations(scenario.note, raw=True))
    stage = StageResult(
        stage="redactor",
        sent={"note": "U-01", "marked_kinds": ["name", "phone"]},
        result={
            "redactor_version": "1.0.0",
            "locations_read": list(pii.LOCATIONS),
            "values": lines,
        },
        outcome=outcome,
        exception_id=UNIT_EXCEPTION_ID,
        audit_event_ids=(),
    )
    result = AttackResult("unit-test", UNIT_EXCEPTION_ID, "0" * 32, (stage,))
    document = attack_dev.evidence_document(result, scenario_file="unit.json")
    rendered = json.dumps(document) + "\n".join(summary_lines(result))
    for item in scenario.note.marked:
        assert item.value not in rendered
        assert item.label in rendered
    assert UNIT_EXCEPTION_ID in rendered and "generated_at" in document
    assert document["stage_order"] == list(STAGES)


def test_the_development_scenario_file_is_a_usable_scenario(tmp_path: Path) -> None:
    """The supplied development scenario parses, and `poe attack-dev` writes where it is told."""
    text = (TASK_ROOT / attack_dev.SCENARIO_PATH).read_text(encoding="utf-8")
    scenario = load_scenario_text(text, require_expected=False)
    assert scenario.scenario_id == "attack-dev"
    assert scenario.note.marked
    document = attack_dev.evidence_document(_result(), scenario_file="x.json")
    target = tmp_path / "evidence" / "attack-dev.json"
    attack_dev.write_evidence(document, target)
    assert json.loads(target.read_text(encoding="utf-8"))["scenario_file"] == "x.json"


def test_the_stage_names_and_outcomes_are_the_policy_vocabulary() -> None:
    """The four stage names and three outcomes are what the decision policy and docs read."""
    assert STAGES == ("token_check", "output_schema", "redactor", "audit_trail")
    assert attack_scenario.OUTCOMES == ("held", "limited", "failed")
    policy = (TASK_ROOT / "docs/governance/decision-policy.md").read_text(encoding="utf-8")
    for word in (*STAGES, *attack_scenario.OUTCOMES):
        assert f"`{word}`" in policy, word
