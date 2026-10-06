"""Coldline.

===================

File:              tests/student/test_redaction.py
Component:         Student tests — PII redaction (supplied Task 4.4 completion)
Purpose:           The two redaction tests: no marked PII from N-01 or pii-echo reaches
                    any location, and the redactor's output on the limitation note is
                    pinned.
Interacts With:    tests/security/interaction.py, src/worker/use_cases.py,
                    src/common/redactor.py, docs/security/redactor.md,
                    tests/fixtures/pii/notes.yaml, src/adapters/model/deterministic.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.4
Concepts:          Deterministic negative tests, redaction before the first copy, a
                    limitation recorded on purpose
Tools:             Python 3.12, pytest

Supplied Task 4.4 completion, carried forward unchanged. These tests are not
student-editable in Task 4.5; `poe student-tests` still runs them beside the carried Task
4.3 and Task 4.2 tests, so the redaction you keep in place is checked on every run.
"""

import pytest

from tests.security.interaction import InteractionHarness


@pytest.fixture
def harness() -> InteractionHarness:
    """Return a fresh in-process worker and API over their own memory store and sink."""
    return InteractionHarness()


# --- Test 1 of 2: the expected redaction.
async def test_no_marked_pii_from_n01_or_pii_echo_reaches_any_location(
    harness: InteractionHarness,
) -> None:
    """Both runs complete with the expected redacted summary and a clean scan.

    N-01 carries a phone number and an email address in the handling note; pii-echo
    adds a contact number in the answer that no request held. The note-side redaction
    keeps the first pair out of the worker logs and the model request; the answer-side
    redaction keeps every marked value out of the stored summary and the audit records.
    """
    n01 = await harness.run_worker("valid", note="N-01")

    assert n01.state == "COMPLETED"
    assert n01.summary == harness.expected_summary(n01.exception_id)
    assert harness.pii_findings(n01.exception_id, note="N-01") == []

    echo = await harness.run_worker("pii-echo")

    assert echo.state == "COMPLETED"
    assert echo.summary == harness.expected_summary(echo.exception_id)
    assert harness.pii_findings(echo.exception_id, response="pii-echo") == []


# --- Test 2 of 2: the limitation.
def test_rl_04_a_capitalized_place_after_a_contact_cue_is_redacted_as_a_name(
    harness: InteractionHarness,
) -> None:
    """RL-04 remains: in N-05 the depot after `Contact` is redacted as a name.

    The redactor recognizes a contact name by position alone, so the capitalized
    place name directly after the cue is replaced although the fixture marks no
    personal detail in this note. The risk that remains is operational: a note can
    lose where to go or which team to reach, and nothing downstream can tell a
    redacted place from a redacted person. This test pins the module's actual output
    so a change in it is noticed.
    """
    assert harness.redact(harness.note("N-05")) == (
        "Contact [REDACTED:name] before the pallet moves; the cold room there holds it "
        "until collection."
    )
