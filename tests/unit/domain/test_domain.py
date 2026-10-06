"""Coldline.

===================

File:              tests/unit/domain/test_domain.py
Component:         Unit tests — Test Domain
Purpose:           Unit tests for the Coldline exception domain.
Interacts With:    One isolated source responsibility
Sprint/Task:       Sprint 4 — Project 4
Concepts:          Fast feedback, failure paths, state invariants
Tools:             Python 3.12, pytest, Pydantic
"""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from domain import exception_id_for, requires_exception
from domain.contracts import ExceptionState, SensorReading
from domain.redaction import redact_sensitive_text, redact_sensor_reading


def reading(temperature_c: float = 9.2, **extras: str) -> SensorReading:
    """Return a fixed synthetic reading for domain tests."""
    return SensorReading(
        reading_id="reading-syn-001",
        shipment_id="shipment-syn-001",
        temperature_c=temperature_c,
        allowed_min_c=2.0,
        allowed_max_c=8.0,
        recorded_at=datetime(2026, 8, 28, tzinfo=UTC),
        **extras,
    )


def test_out_of_range_reading_requires_exception() -> None:
    """An upper-bound excursion must enter the exception path."""
    assert requires_exception(reading()) is True


def test_in_range_reading_does_not_require_exception() -> None:
    """A reading inside its handling range must not create exception work."""
    assert requires_exception(reading(5.0)) is False


def test_invalid_handling_range_is_rejected() -> None:
    """A reversed temperature range must fail before external work occurs."""
    with pytest.raises(ValidationError):
        SensorReading(
            reading_id="reading-syn-001",
            shipment_id="shipment-syn-001",
            temperature_c=5.0,
            allowed_min_c=8.0,
            allowed_max_c=2.0,
            recorded_at=datetime(2026, 8, 28, tzinfo=UTC),
        )


def test_exception_identity_is_stable_for_duplicate_reading() -> None:
    """Replaying one reading must address the same exception record."""
    assert exception_id_for(reading()) == "exc-e6a7451a-fe1a-53ca-b280-9bf67f555977"


def test_exception_states_are_the_published_state_machine() -> None:
    """The shared contract exposes the documented lifecycle states, NEEDS_REVIEW included."""
    assert [state.value for state in ExceptionState] == [
        "RECEIVED",
        "QUEUED",
        "PROCESSING",
        "COMPLETED",
        "FAILED",
        "NEEDS_REVIEW",
    ]


def test_handling_note_is_optional_bounded_free_text() -> None:
    """A reading may carry a note, may leave it out, and may not exceed the bound."""
    assert reading().handling_note is None
    assert reading(handling_note="Re-ice at the relay.").handling_note == "Re-ice at the relay."
    with pytest.raises(ValidationError):
        reading(handling_note="x" * 1_001)


def test_reading_still_rejects_an_unknown_field() -> None:
    """Adding the note did not loosen the closed reading contract."""
    with pytest.raises(ValidationError):
        reading(handling_notes="misspelled field")


def test_sensitive_text_is_redacted_before_logging_or_model_use() -> None:
    """Common identifying fields must not cross the supplied redaction boundary."""
    raw = "name=Ada Lovelace email=ada@example.test phone=+1 555 0100"
    assert redact_sensitive_text(raw) == "name=[REDACTED] email=[REDACTED] phone=[REDACTED]"


def test_single_token_name_does_not_consume_the_next_context_field() -> None:
    """A bounded name value must be removed without hiding unrelated evidence."""
    raw = "name=Ada zone=west status=delayed"
    assert redact_sensitive_text(raw) == "name=[REDACTED] zone=west status=delayed"


def test_multiline_name_and_phone_are_redacted_without_hiding_operations() -> None:
    """Newlines and semicolons must bound PII without consuming operational text."""
    raw = "name=Ada Lovelace\nphone=+1 555 0100; shipment delayed"
    assert redact_sensitive_text(raw) == ("name=[REDACTED]\nphone=[REDACTED]; shipment delayed")


def test_supplied_redaction_covers_the_context_field_and_not_the_handling_note() -> None:
    """The Sprint 1 redaction reads `context` only; a free-text note passes through as written.

    This pins the opening checkpoint's behavior, not a desired one: the note is
    carried raw into the record, the queue, and the model request.
    """
    note = "Call Priya Natarajan on +1 555 0142 or priya.natarajan@example.test."
    redacted = redact_sensor_reading(
        reading(context="carrier email=ada@example.test", handling_note=note)
    )

    assert redacted.context == "carrier email=[REDACTED]"
    assert redacted.handling_note == note
