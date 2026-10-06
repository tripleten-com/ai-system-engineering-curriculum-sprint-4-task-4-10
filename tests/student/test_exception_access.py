"""Coldline.

===================

File:              tests/student/test_exception_access.py
Component:         Student tests — Exception summary access (supplied Task 4.2 completion)
Purpose:           The eight access tests for GET /api/v1/exceptions/{exception_id}: one
                    allowed read and seven refusals.
Interacts With:    tests/security/harness.py, config/auth.yaml, src/api/routes.py,
                    tests/fixtures/tokens/fixtures.yaml
Sprint/Task:       Sprint 4 — Project 4 / Task 4.2
Concepts:          Negative authorization tests, exact status assertions, 401 versus 403
Tools:             Python 3.12, pytest, httpx

Supplied Task 4.2 completion, carried forward from Task 4.7 on: one test per fixture, each
creating its own exception with a stored summary, asserting the exact status, and asserting
that the summary text does not come back on a refusal. These tests are not student-editable
in Task 4.7; `poe student-tests` runs them beside the carried Task 4.3 and Task 4.4 tests
(they need the issuer running, as `README.md` says), so the access rule you inherited is
checked on every run.
"""

import pytest

from tests.security.harness import AccessHarness


@pytest.fixture
def harness() -> AccessHarness:
    """Return a fresh in-process API, its memory store, and the token loader, for one test."""
    return AccessHarness()


# --- Test 1 of 8: `dispatcher-valid` is allowed.
async def test_dispatcher_valid_reads_the_stored_summary(harness: AccessHarness) -> None:
    """The dispatcher's token reads the record, with its id and the summary that was stored."""
    exception_id, summary = harness.stored_exception()
    async with harness.bearer_client("dispatcher-valid") as client:
        response = await client.get(f"/api/v1/exceptions/{exception_id}")

    assert response.status_code == 200
    body = response.json()
    assert body["exception_id"] == exception_id
    assert body["summary"] == summary


# --- Test 2 of 8: `bad-signature` is refused.
async def test_bad_signature_is_refused_with_401(harness: AccessHarness) -> None:
    """A token signed by another key is not identified: 401, and no summary comes back."""
    exception_id, summary = harness.stored_exception()
    async with harness.bearer_client("bad-signature") as client:
        response = await client.get(f"/api/v1/exceptions/{exception_id}")

    assert response.status_code == 401
    assert summary not in response.text


# --- Test 3 of 8: `wrong-issuer` is refused.
async def test_wrong_issuer_is_refused_with_401(harness: AccessHarness) -> None:
    """A token from another issuer is not identified: 401, and no summary comes back."""
    exception_id, summary = harness.stored_exception()
    async with harness.bearer_client("wrong-issuer") as client:
        response = await client.get(f"/api/v1/exceptions/{exception_id}")

    assert response.status_code == 401
    assert summary not in response.text


# --- Test 4 of 8: `wrong-audience` is refused.
async def test_wrong_audience_is_refused_with_401(harness: AccessHarness) -> None:
    """A token issued for another API is not accepted here: 401, and no summary comes back."""
    exception_id, summary = harness.stored_exception()
    async with harness.bearer_client("wrong-audience") as client:
        response = await client.get(f"/api/v1/exceptions/{exception_id}")

    assert response.status_code == 401
    assert summary not in response.text


# --- Test 5 of 8: `expired` is refused.
async def test_expired_is_refused_with_401(harness: AccessHarness) -> None:
    """A token past its expiry and the leeway is not accepted: 401, and no summary comes back."""
    exception_id, summary = harness.stored_exception()
    async with harness.bearer_client("expired") as client:
        response = await client.get(f"/api/v1/exceptions/{exception_id}")

    assert response.status_code == 401
    assert summary not in response.text


# --- Test 6 of 8: `gateway-valid` is refused.
async def test_gateway_valid_is_refused_with_403(harness: AccessHarness) -> None:
    """A sensor gateway is identified but not granted summaries: 403, and no summary comes back."""
    exception_id, summary = harness.stored_exception()
    async with harness.bearer_client("gateway-valid") as client:
        response = await client.get(f"/api/v1/exceptions/{exception_id}")

    assert response.status_code == 403
    assert summary not in response.text


# --- Test 7 of 8: `wrong-role` is refused.
async def test_wrong_role_is_refused_with_403(harness: AccessHarness) -> None:
    """The read scope under a role the policy does not grant: 403, and no summary comes back."""
    exception_id, summary = harness.stored_exception()
    async with harness.bearer_client("wrong-role") as client:
        response = await client.get(f"/api/v1/exceptions/{exception_id}")

    assert response.status_code == 403
    assert summary not in response.text


# --- Test 8 of 8: `missing-scope` is refused.
async def test_missing_scope_is_refused_with_403(harness: AccessHarness) -> None:
    """A dispatcher token issued without the read scope: 403, and no summary comes back."""
    exception_id, summary = harness.stored_exception()
    async with harness.bearer_client("missing-scope") as client:
        response = await client.get(f"/api/v1/exceptions/{exception_id}")

    assert response.status_code == 403
    assert summary not in response.text
