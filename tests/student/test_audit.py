"""Coldline.

===================

File:              tests/student/test_audit.py
Component:         Student tests — Audit trail (supplied Task 4.3 completion)
Purpose:           The two audit tests: one interaction leaves every listed event in order, and
                    no audit record contains a credential.
Interacts With:    tests/security/interaction.py, src/worker/use_cases.py, src/api/routes.py,
                    src/common/audit.py, docs/security/audit-events.md,
                    tests/fixtures/tokens/fixtures.yaml, tests/fixtures/credentials/test-values.yaml
Sprint/Task:       Sprint 4 — Project 4 / Task 4.3
Concepts:          Audit trail as evidence, credentials never recorded, deterministic tests
Tools:             Python 3.12, pytest, httpx

Supplied Task 4.3 completion, carried forward unchanged. These tests are not student-editable
in Task 4.4; `poe student-tests` still runs them beside your `test_redaction.py` (they need
the issuer running, as `README.md` says), so the audit events you keep in place are checked
on every run.
"""

import pytest

from tests.security.interaction import InteractionHarness


@pytest.fixture
def harness() -> InteractionHarness:
    """Return a fresh in-process worker and API, with their own memory store and audit sink."""
    return InteractionHarness()


# --- Test 1 of 2: one interaction leaves every listed event, in order.
async def test_one_interaction_leaves_every_listed_event_in_order(
    harness: InteractionHarness,
) -> None:
    """The four worker events in their order, then the one summary read with subject and role."""
    record = await harness.run_worker("manipulated")
    async with harness.bearer_client("dispatcher-valid") as client:
        response = await client.get(f"/api/v1/exceptions/{record.exception_id}")

    assert response.status_code == 200
    trail = harness.audit_trail(record.exception_id)
    assert [entry.event for entry in trail] == [
        "processing_requested",
        "model_responded",
        "output_rejected",
        "outcome_stored",
        "summary_read",
    ]
    assert all(entry.exception_id == record.exception_id for entry in trail)
    responded = trail[1]
    assert len(responded.details["answer_digest"]) == 64
    assert responded.details["answer_length"] > 0
    assert trail[2].details["reason_code"] == record.rejection_reason
    assert trail[3].details["state"] == "NEEDS_REVIEW"
    assert trail[3].details["summary"] == harness.review_message
    read = trail[4]
    assert read.details["subject"] == "user:dispatcher-01"
    assert read.details["role"] == "dispatcher"


# --- Test 2 of 2: no audit record contains a credential.
async def test_no_audit_record_contains_a_credential(harness: InteractionHarness) -> None:
    """Neither the token, nor the header name in any case, nor a supplied secret is in the trail."""
    record = await harness.run_worker("valid")
    async with harness.bearer_client("dispatcher-valid") as client:
        response = await client.get(f"/api/v1/exceptions/{record.exception_id}")

    assert response.status_code == 200
    text = harness.audit_text(record.exception_id)
    assert text
    assert harness.token("dispatcher-valid") not in text
    assert "authorization" not in text.lower()
    for secret in harness.secret_values():
        assert secret not in text
