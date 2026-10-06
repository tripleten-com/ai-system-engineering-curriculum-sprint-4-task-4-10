"""Coldline.

===================

File:              tests/security/token_check.py
Component:         Security tooling — Token check
Purpose:           Run one token fixture through the supplied verifier as config/auth.yaml
                    configures it.
Interacts With:    config/auth.yaml, tests/fixtures/tokens/fixtures.yaml, the issuer's key set
Sprint/Task:       Sprint 4 — Project 4 / Task 4.3
Concepts:          Signature, issuer, audience, expiry, reasons that name the failed claim
Tools:             Python 3.12

``poe token-check <fixture>`` prints ``accepted`` (then the principal on a second line) or
``rejected: <reason>``. It reads ``config/auth.yaml`` directly, so no API rebuild is needed
between edits; the key set is fetched from the ``jwks_url`` it names, so the issuer must be
running. Exit 0 for accepted, 1 for rejected, 2 for a usage or configuration error.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from api.security.tokens import AuthConfigError, TokenError, TokenVerifier
from tests.security.fixtures import FIXTURE_NAMES, token
from tests.security.issuer_origin import host_issuer_origin

TASK_ROOT = Path(__file__).resolve().parents[2]
AUTH_CONFIG_PATH = TASK_ROOT / "config/auth.yaml"


def main(argv: list[str] | None = None) -> int:
    """Verify one named fixture and print the verdict."""
    parser = argparse.ArgumentParser(description="Run one token fixture through the verifier.")
    parser.add_argument("fixture", help=f"one of: {', '.join(FIXTURE_NAMES)}")
    arguments = parser.parse_args(argv)
    try:
        credential = token(arguments.fixture)
    except ValueError as exc:
        print(f"token-check: {exc}", file=sys.stderr)
        return 2
    try:
        verifier = TokenVerifier.from_config(AUTH_CONFIG_PATH, jwks_origin=host_issuer_origin())
    except AuthConfigError as exc:
        print(f"token-check: {exc}", file=sys.stderr)
        return 2
    try:
        principal = verifier.verify(credential)
    except TokenError as exc:
        print(f"rejected: {exc.reason}")
        return 1
    print("accepted")
    scopes = " ".join(sorted(principal.scopes)) or "-"
    print(f"  subject={principal.subject} role={principal.role} scope={scopes}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
