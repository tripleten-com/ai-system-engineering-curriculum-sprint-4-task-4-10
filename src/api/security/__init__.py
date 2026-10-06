"""Coldline.

===================

File:              src/api/security/__init__.py
Component:         API — Security package
Purpose:           Token verification and the role-and-scope access rule for API routes.
Interacts With:    config/auth.yaml, the development issuer's key set, src/api/routes.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.2
Concepts:          Bearer tokens, OIDC discovery, JWKS, least privilege
Tools:             Python 3.12, FastAPI, PyJWT

Supplied and settled from Task 4.2 on. ``tokens`` verifies a bearer token against the
issuer named in ``config/auth.yaml``; ``access`` applies one role-and-scope rule to a
route. Neither module is student-editable: the Task configures the verifier through
``config/auth.yaml`` and applies ``require_access`` in ``src/api/routes.py``.
"""

from api.security.access import AccessDenied, check_access, require_access
from api.security.tokens import (
    AuthConfigError,
    AuthSettings,
    Principal,
    TokenError,
    TokenVerifier,
    load_auth_settings,
)

__all__ = [
    "AccessDenied",
    "AuthConfigError",
    "AuthSettings",
    "Principal",
    "TokenError",
    "TokenVerifier",
    "check_access",
    "load_auth_settings",
    "require_access",
]
