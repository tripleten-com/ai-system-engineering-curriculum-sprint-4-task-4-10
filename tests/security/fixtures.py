"""Coldline.

===================

File:              tests/security/fixtures.py
Component:         Security tooling — Token fixture loader
Purpose:           Load the eight supplied tokens by fixture name and build bearer headers.
Interacts With:    tests/fixtures/tokens/fixtures.yaml, every caller of the summary endpoint
Sprint/Task:       Sprint 4 — Project 4 / Task 4.2
Concepts:          Token fixtures, bearer authentication, expected outcomes
Tools:             Python 3.12, PyYAML

The fixture file maps each name to one compact JWT, signed once with the development
issuer's key. This module is the one place the names and their expected outcomes live:
the supplied scenario and e2e checks read summaries with ``dispatcher-valid``, and the
assessed checks and ``poe auth-checks`` walk the eight names in the Task's table order.
"""

from __future__ import annotations

from pathlib import Path

import yaml

TASK_ROOT = Path(__file__).resolve().parents[2]
FIXTURES_PATH = TASK_ROOT / "tests/fixtures/tokens/fixtures.yaml"
# The one token the protected summary read accepts.
ALLOWED: tuple[str, ...] = ("dispatcher-valid",)
# Valid tokens the access rule refuses: 403 once the route is protected.
UNAUTHORIZED: tuple[str, ...] = ("gateway-valid", "wrong-role", "missing-scope")
# Invalid tokens the verifier refuses: 401 once the route is protected.
INVALID: tuple[str, ...] = ("bad-signature", "wrong-issuer", "wrong-audience", "expired")
# The seven the endpoint refuses, in the order the Task lists them.
REFUSED: tuple[str, ...] = INVALID + UNAUTHORIZED
# All eight, in the order the Task's table shows them.
FIXTURE_NAMES: tuple[str, ...] = ALLOWED + UNAUTHORIZED + INVALID
EXPECTED_STATUS: dict[str, int] = {
    **dict.fromkeys(ALLOWED, 200),
    **dict.fromkeys(UNAUTHORIZED, 403),
    **dict.fromkeys(INVALID, 401),
}


def load_fixtures(path: Path = FIXTURES_PATH) -> dict[str, str]:
    """Return every fixture token by name, in file order."""
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    fixtures = document.get("fixtures") if isinstance(document, dict) else None
    if not isinstance(fixtures, dict) or not all(
        isinstance(name, str) and isinstance(value, str) for name, value in fixtures.items()
    ):
        raise ValueError(f"{path.name} must map fixture names to compact tokens under `fixtures:`")
    return dict(fixtures)


def token(name: str, *, path: Path = FIXTURES_PATH) -> str:
    """Return one fixture's compact token, or raise naming the fixtures that exist."""
    fixtures = load_fixtures(path)
    if name not in fixtures:
        raise ValueError(f"unknown token fixture {name!r}; choose one of {', '.join(fixtures)}")
    return fixtures[name]


def bearer_headers(name: str, *, path: Path = FIXTURES_PATH) -> dict[str, str]:
    """Return the Authorization header that sends one fixture as a bearer token."""
    return {"Authorization": f"Bearer {token(name, path=path)}"}
