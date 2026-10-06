"""Coldline.

===================

File:              tests/student/test_output_guardrail.py
Component:         Student tests — Output guardrail (supplied Task 4.3 completion)
Purpose:           The three guardrail tests: the valid answer is stored, and the malformed and
                    manipulated answers each end in NEEDS_REVIEW with the fixed message.
Interacts With:    tests/security/interaction.py, src/worker/use_cases.py,
                    src/worker/guardrail.py, schemas/exception-summary.schema.json,
                    docs/security/output-policy.md
Sprint/Task:       Sprint 4 — Project 4 / Task 4.3
Concepts:          Deterministic negative tests, fail-safe outcomes, supplied bad answers
Tools:             Python 3.12, pytest

Supplied Task 4.3 completion, carried forward unchanged. These tests are not student-editable
in Task 4.4; `poe student-tests` still runs them beside your `test_redaction.py`, so the
guardrail you keep in place is checked on every run.
"""

import pytest

from tests.security.interaction import InteractionHarness


@pytest.fixture
def harness() -> InteractionHarness:
    """Return a fresh in-process worker and API, with their own memory store and audit sink."""
    return InteractionHarness()


# --- Test 1 of 3: the valid response.
async def test_valid_answer_is_stored_with_its_schema_fields(harness: InteractionHarness) -> None:
    """The valid answer ends in COMPLETED with the validated summary, class and step."""
    record = await harness.run_worker("valid")

    assert record.state == "COMPLETED"
    assert record.summary is not None
    assert record.summary.startswith("Synthetic shipment")
    assert record.summary != harness.review_message
    assert record.handling_class == "thermal_excursion"
    assert record.next_step == "operational_review"
    assert record.rejection_reason is None


# --- Test 2 of 3: the malformed response.
async def test_malformed_answer_needs_review_with_the_fixed_message(
    harness: InteractionHarness,
) -> None:
    """An answer that stops partway is refused whole: NEEDS_REVIEW, the fixed message, a code."""
    record = await harness.run_worker("malformed")

    assert record.state == "NEEDS_REVIEW"
    assert record.summary == harness.review_message
    assert record.rejection_reason is not None
    assert record.rejection_reason.split(":")[0] in harness.reason_codes
    assert record.handling_class is None
    assert record.next_step is None


# --- Test 3 of 3: the manipulated response.
async def test_manipulated_answer_needs_review_with_the_fixed_message(
    harness: InteractionHarness,
) -> None:
    """Well-formed JSON outside the schema is refused the same way, with none of its text."""
    record = await harness.run_worker("manipulated")

    assert record.state == "NEEDS_REVIEW"
    assert record.summary == harness.review_message
    assert record.rejection_reason is not None
    assert record.rejection_reason.split(":")[0] in harness.reason_codes
    assert record.handling_class is None
    assert record.next_step is None
