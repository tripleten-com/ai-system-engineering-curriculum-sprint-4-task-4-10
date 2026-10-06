"""Coldline.

===================

File:              tests/unit/api/test_require_access.py
Component:         Unit tests — Access rule
Purpose:           Prove the supplied rule's 401 and 403 decisions and the principal it yields.
Interacts With:    src/api/security/access.py, src/api/security/tokens.py, tests/security/harness.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.2
Concepts:          Authentication versus authorization, 401 versus 403, least privilege
Tools:             Python 3.12, pytest, httpx, FastAPI

The rule is exercised on a small application of its own, not on the exception route, and
with the gateway's row of the access policy, so this file neither applies nor reveals the
summary-read rule the Task asks for. The key set is the committed file.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import httpx
import pytest
from fastapi import Depends, FastAPI

from api.security.access import AccessDenied, check_access, require_access
from api.security.tokens import AuthSettings, Principal, TokenVerifier
from tests.security.fixtures import token

TASK_ROOT = Path(__file__).resolve().parents[3]
KEY_SET = TASK_ROOT / "infra/issuer/jwks.json"


def _verifier() -> TokenVerifier:
    """Return a verifier over the committed key set."""
    settings = AuthSettings(
        issuer="https://issuer.coldline.test",
        audience="coldline-api",
        jwks_url="http://localhost:8180/.well-known/jwks.json",
        algorithms=["RS256"],
        leeway_seconds=30,
    )
    return TokenVerifier(settings, fetch=lambda url: KEY_SET.read_bytes())


def _app(verifier: TokenVerifier | None) -> FastAPI:
    """Return one route guarded by the gateway's row, plus one open route."""
    app = FastAPI()
    app.state.token_verifier = verifier

    @app.post("/guarded")
    async def guarded(
        principal: Annotated[
            Principal, Depends(require_access(role="sensor_gateway", scope="readings:write"))
        ],
    ) -> dict[str, str]:
        """Echo the principal so the test sees what the route received."""
        return {"subject": principal.subject, "role": principal.role}

    @app.get("/open")
    async def open_route() -> dict[str, str]:
        """Stay open, as every route without the rule does."""
        return {"status": "open"}

    return app


async def _call(app: FastAPI, path: str, headers: dict[str, str] | None = None) -> httpx.Response:
    """Send one request to the in-process application."""
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        if path == "/guarded":
            return await client.post(path, headers=headers)
        return await client.get(path, headers=headers)


def _bearer(name: str) -> dict[str, str]:
    """Return the bearer header for one fixture."""
    return {"Authorization": f"Bearer {token(name)}"}


async def test_the_granted_role_and_scope_reach_the_route_as_a_principal() -> None:
    """A verified token with the row's role and scope is admitted and the route sees who."""
    response = await _call(_app(_verifier()), "/guarded", _bearer("gateway-valid"))

    assert response.status_code == 200
    assert response.json()["role"] == "sensor_gateway"


async def test_no_token_and_a_non_bearer_header_are_401() -> None:
    """Without a bearer token the caller is unidentified: 401, with WWW-Authenticate."""
    app = _app(_verifier())

    missing = await _call(app, "/guarded")
    assert missing.status_code == 401
    assert missing.headers.get("www-authenticate") == "Bearer"
    assert "missing" in missing.json()["detail"]

    basic = await _call(app, "/guarded", {"Authorization": "Basic Zm9vOmJhcg=="})
    assert basic.status_code == 401
    assert "not a bearer token" in basic.json()["detail"]


@pytest.mark.parametrize("fixture", ["bad-signature", "wrong-issuer", "wrong-audience", "expired"])
async def test_a_refused_token_is_401_with_the_verifier_reason(fixture: str) -> None:
    """An authentication failure carries the verifier's reason in the body."""
    response = await _call(_app(_verifier()), "/guarded", _bearer(fixture))

    assert response.status_code == 401
    assert response.json()["detail"].startswith("token rejected: ")


async def test_a_verified_token_with_another_role_is_403() -> None:
    """A dispatcher is identified but not granted the gateway's action."""
    response = await _call(_app(_verifier()), "/guarded", _bearer("dispatcher-valid"))

    assert response.status_code == 403
    assert "role claim" in response.json()["detail"]
    assert "sensor_gateway" not in response.json()["detail"], "the rule is not echoed"


def test_a_verified_token_with_the_role_but_not_the_scope_is_403() -> None:
    """The role alone does not grant; the scope must be in the token too."""
    with pytest.raises(AccessDenied) as refused:
        check_access(
            _verifier(),
            f"Bearer {token('gateway-valid')}",
            role="sensor_gateway",
            scope="exceptions:read",
        )

    assert refused.value.kind == "permission_denied"
    assert "scope claim" in refused.value.reason


async def test_a_route_without_the_rule_stays_open() -> None:
    """Applying the rule to one route changes nothing for the others."""
    response = await _call(_app(_verifier()), "/open")

    assert response.status_code == 200


async def test_an_application_composed_without_a_verifier_fails_loudly() -> None:
    """A missing verifier is a composition defect (500), never an admission."""
    response = await _call(_app(None), "/guarded", _bearer("gateway-valid"))

    assert response.status_code == 500


def test_require_access_rejects_a_blank_rule() -> None:
    """A rule with no role or no scope cannot be built."""
    with pytest.raises(ValueError, match="non-empty role and scope"):
        require_access(role="", scope="readings:write")
