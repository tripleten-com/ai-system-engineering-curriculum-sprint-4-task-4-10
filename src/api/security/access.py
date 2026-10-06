"""Coldline.

===================

File:              src/api/security/access.py
Component:         API — Access rule
Purpose:           Verify the caller's token and apply one role-and-scope rule to a route.
Interacts With:    api.security.tokens, src/api/routes.py, docs/security/access-policy.md
Sprint/Task:       Sprint 4 — Project 4 / Task 4.2
Concepts:          Authentication versus authorization, least privilege, 401 versus 403
Tools:             Python 3.12, FastAPI

Supplied and settled: apply it, do not edit it. ``require_access(role=..., scope=...)``
returns a FastAPI dependency. The dependency reads the request's ``Authorization`` header,
runs ``TokenVerifier.verify`` on the bearer token, and then applies the rule:

- no token, a non-bearer header, or a token the verifier refuses: **401**, with the
  verifier's reason in ``detail`` (the caller could not be identified);
- a verified token whose role is not the one granted, or whose scopes do not include the
  one granted: **403** (the caller was identified but is not allowed);
- otherwise the route receives the verified ``Principal``.

Call form, in ``src/api/routes.py``::

    from typing import Annotated

    from fastapi import Depends

    from api.security.access import require_access
    from api.security.tokens import Principal

    @app.get("/api/v1/exceptions/{exception_id}", response_model=ExceptionRecord)
    async def get_exception(
        exception_id: str,
        principal: Annotated[
            Principal, Depends(require_access(role="<role>", scope="<scope>"))
        ],
    ) -> ExceptionRecord:
        ...

``role`` and ``scope`` are the one row of ``docs/security/access-policy.md`` that grants the
action the route performs. Because the dependency runs the verification itself, removing it
removes both checks at once: the route then answers every caller, token or not.

``check_access`` is the same decision without FastAPI, for a transport that is not HTTP
(the optional gRPC ingest reuses it): it raises ``AccessDenied`` with ``kind``
``unauthenticated`` or ``permission_denied``.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Literal

from fastapi import HTTPException, Request

from api.security.tokens import Principal, TokenError, TokenVerifier

Kind = Literal["unauthenticated", "permission_denied"]
# The HTTP status for each kind of refusal. `tests/security/mutation.py` swaps the two
# values in a temporary copy of this module to prove a student's rejection tests assert the
# exact status rather than "anything but 200".
STATUS_BY_KIND: dict[str, int] = {"unauthenticated": 401, "permission_denied": 403}


class AccessDenied(Exception):
    """Report a refused request: the kind decides the status, the reason says why."""

    def __init__(self, kind: Kind, reason: str) -> None:
        """Keep both parts as attributes so any transport can map them."""
        super().__init__(reason)
        self.kind: Kind = kind
        self.reason = reason


def check_access(
    verifier: TokenVerifier, authorization: str | None, *, role: str, scope: str
) -> Principal:
    """Verify the bearer credential in ``authorization`` and apply the role-and-scope rule.

    Transport-neutral: the HTTP dependency below and any other carrier of a bearer token
    (gRPC metadata, for example) call this and map ``AccessDenied.kind`` to their own
    status. Authentication failures come first and name the verifier's reason;
    authorization failures name the claim that fell short without echoing the rule.
    """
    if authorization is None:
        raise AccessDenied(
            "unauthenticated", "no bearer token: the Authorization header is missing"
        )
    scheme, _, credential = authorization.strip().partition(" ")
    credential = credential.strip()
    if scheme.lower() != "bearer" or not credential:
        raise AccessDenied("unauthenticated", "the Authorization header is not a bearer token")
    try:
        principal = verifier.verify(credential)
    except TokenError as exc:
        raise AccessDenied("unauthenticated", f"token rejected: {exc.reason}") from exc
    if principal.role != role:
        raise AccessDenied(
            "permission_denied", f"role claim {principal.role!r} is not granted this action"
        )
    if scope not in principal.scopes:
        raise AccessDenied(
            "permission_denied", "scope claim does not include the scope this action needs"
        )
    return principal


def require_access(*, role: str, scope: str) -> Callable[[Request], Awaitable[Principal]]:
    """Return a FastAPI dependency that admits one role with one scope and refuses the rest.

    See the module docstring for the call form. The verifier is the one ``create_app``
    composed into ``app.state.token_verifier``; an application composed without one is a
    composition defect and fails loudly rather than admitting anyone.
    """
    if not role.strip() or not scope.strip():
        raise ValueError("require_access needs a non-empty role and scope")

    async def dependency(request: Request) -> Principal:
        """Admit the request's caller or raise the matching HTTP refusal."""
        verifier = getattr(request.app.state, "token_verifier", None)
        if not isinstance(verifier, TokenVerifier):
            raise RuntimeError(
                "the application was composed without a TokenVerifier; "
                "pass token_verifier= to create_app"
            )
        try:
            return check_access(
                verifier, request.headers.get("authorization"), role=role, scope=scope
            )
        except AccessDenied as exc:
            headers = {"WWW-Authenticate": "Bearer"} if exc.kind == "unauthenticated" else None
            raise HTTPException(
                status_code=STATUS_BY_KIND[exc.kind], detail=exc.reason, headers=headers
            ) from exc

    return dependency
