"""Coldline.

===================

File:              tests/unit/common/test_redactor.py
Component:         Unit tests — PII redactor
Purpose:           Prove the supplied redactor replaces the forms its documentation names with
                    the documented placeholders, leaves the output's shape intact, and is stable.
Interacts With:    src/common/redactor.py, docs/security/redactor.md,
                    schemas/exception-summary.schema.json
Sprint/Task:       Sprint 4 — Project 4 / Task 4.4
Concepts:          Deterministic text rules, placeholders, idempotence, output shape preserved
Tools:             Python 3.12, pytest

The probes here are synthetic phrases, not the supplied notes: which supplied note the
redactor handles wrongly, and how, is the student's finding, so no test in this file reads
``tests/fixtures/pii/notes.yaml`` or pins a documented limitation.
"""

from __future__ import annotations

import json

import pytest

from common.redactor import (
    KINDS,
    MAXIMUM_PHONE_DIGITS,
    MINIMUM_PHONE_DIGITS,
    NAME_CUES,
    REDACTOR_VERSION,
    placeholder,
    redact,
)
from worker.guardrail import ValidatedSummary, validate_summary


def test_the_version_the_kinds_and_the_placeholders_are_the_documented_ones() -> None:
    """The constants the documentation quotes are what the module exports."""
    assert REDACTOR_VERSION == "1.0.0"
    assert KINDS == ("email", "phone", "name")
    assert NAME_CUES == ("call", "contact", "ask for", "notify", "reach", "page")
    assert (MINIMUM_PHONE_DIGITS, MAXIMUM_PHONE_DIGITS) == (7, 15)
    for kind in KINDS:
        assert placeholder(kind) == f"[REDACTED:{kind}]"
    with pytest.raises(ValueError, match="unknown redaction kind"):
        placeholder("address")


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("ring 555-0100 before noon", "ring [REDACTED:phone] before noon"),
        ("reach the desk on +1 555 0100.", "reach the desk on [REDACTED:phone]."),
        ("dial (555) 0100 twice", "dial [REDACTED:phone] twice"),
        ("try 555.0100 or 555 0100", "try [REDACTED:phone] or [REDACTED:phone]"),
        ("+44 20 5550 0100 is the office", "[REDACTED:phone] is the office"),
    ],
    ids=["hyphen", "country-code", "parentheses", "period-and-space", "four-groups"],
)
def test_phone_numbers_in_the_documented_shapes_are_replaced(text: str, expected: str) -> None:
    """Hyphens, spaces, periods, a country code and parentheses are all recognized."""
    assert redact(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "the cold room is above 8 C",
        "exceeded the upper handling bound by 1.2 C",
        "between 2.0 and 8.0 C for 12.5 hours",
        "shipment-syn-012345678901 exceeded the bound",
        "response id 0123456789abcdef",
        "seal 12345678901234567 is intact",
    ],
    ids=["one-digit", "decimal", "several-short", "hyphenated-id", "hex-id", "too-long"],
)
def test_digit_runs_outside_the_phone_shapes_stay_as_they_are(text: str) -> None:
    """Short numbers, decimals, digits inside an identifier, and over-long runs are left alone."""
    assert redact(text) == text


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("send it to dispatch@example.com today", "send it to [REDACTED:email] today"),
        ("qa-review@example.org, then hold", "[REDACTED:email], then hold"),
        ("(a.okafor+lane2@example.com)", "([REDACTED:email])"),
        ("mail relay.desk@sub.example.org.", "mail [REDACTED:email]."),
    ],
    ids=["plain", "hyphen-local", "plus-and-dot", "subdomain"],
)
def test_email_addresses_are_replaced_whole(text: str, expected: str) -> None:
    """The whole address goes, and the punctuation around it stays."""
    assert redact(text) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Call Priya Natarajan on the desk line", "Call [REDACTED:name] on the desk line"),
        ("please contact Tomasz at the relay", "please contact [REDACTED:name] at the relay"),
        ("Ask for Amara Okafor before noon", "Ask for [REDACTED:name] before noon"),
        ("NOTIFY Jonas when it arrives", "NOTIFY [REDACTED:name] when it arrives"),
        ("page Lin Wei for the release", "page [REDACTED:name] for the release"),
    ],
    ids=["call-two-words", "contact-one-word", "ask-for", "uppercase-cue", "page"],
)
def test_a_capitalized_name_after_a_contact_cue_is_replaced_and_the_cue_stays(
    text: str, expected: str
) -> None:
    """One or two capitalized words after a cue become the name placeholder; the cue stays."""
    assert redact(text) == expected


def test_a_cue_followed_by_lowercase_words_replaces_nothing() -> None:
    """A cue alone does not make the next word a name: it has to be capitalized."""
    text = "reach the night desk and call the relay before the pallet moves"
    assert redact(text) == text


def test_every_kind_is_replaced_in_one_text_and_the_result_is_stable() -> None:
    """Email, then phone, then name are applied; redacting the result changes nothing."""
    text = "Call Priya Natarajan on +1 555 0100 or priya@example.com before the pallet moves."
    redacted = redact(text)

    assert redacted == (
        "Call [REDACTED:name] on [REDACTED:phone] or [REDACTED:email] before the pallet moves."
    )
    assert redact(redacted) == redacted
    for kind in KINDS:
        assert placeholder(kind) in redacted


def test_none_passes_through_and_a_text_without_pii_comes_back_unchanged() -> None:
    """A reading without a note needs no special case; plain text is left alone."""
    assert redact(None) is None
    text = "Keep the seal intact until the lab confirms the cold room is below 8 C."
    assert redact(text) == text
    assert redact("") == ""


def test_a_json_answer_stays_valid_and_inside_the_output_schema_after_redaction() -> None:
    """The placeholders carry no quote or backslash, so a redacted JSON document still parses.

    The valid answer document with a note full of detail in its summary is redacted as the
    worker redacts the raw answer; the result is valid JSON, the schema accepts it, and the
    summary's detail is gone while the identifiers around it are untouched.
    """
    document = {
        "summary": (
            "Synthetic shipment shipment-syn-0123456789ab exceeded the upper handling bound by "
            "1.2 C; operational review is required. Handling note: Call Priya Natarajan on "
            "+1 555 0100 or priya@example.com before the pallet moves."
        ),
        "handling_class": "thermal_excursion",
        "next_step": "operational_review",
        "procedure_id": "playbook-thermal-excursion",
        "response_id": "0123456789abcdef",
    }
    raw = json.dumps(document, sort_keys=True)

    redacted = redact(raw)

    parsed = json.loads(redacted)
    assert parsed["response_id"] == "0123456789abcdef"
    assert parsed["procedure_id"] == "playbook-thermal-excursion"
    assert "shipment-syn-0123456789ab" in parsed["summary"]
    for detail in ("Priya Natarajan", "+1 555 0100", "priya@example.com"):
        assert detail not in redacted
    verdict = validate_summary(redacted)
    assert isinstance(verdict, ValidatedSummary)
    assert verdict.summary.endswith(
        "Handling note: Call [REDACTED:name] on [REDACTED:phone] or [REDACTED:email] before "
        "the pallet moves."
    )
