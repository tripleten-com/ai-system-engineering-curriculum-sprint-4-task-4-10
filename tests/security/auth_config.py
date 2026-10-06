"""Coldline.

===================

File:              tests/security/auth_config.py
Component:         Security tooling — Verification settings check
Purpose:           Check config/auth.yaml against the access policy and the issuer's live
                    discovery document.
Interacts With:    config/auth.yaml, docs/security/access-policy.md, the issuer's discovery document
Sprint/Task:       Sprint 4 — Project 4 / Task 4.2
Concepts:          Pinned algorithms, clock leeway, audience versus issuer, OIDC discovery
Tools:             Python 3.12, httpx

Four findings functions, one per assessed row, each returning the reasons a setting is
not what the policy or the discovery document says (an empty list means it is):

- ``algorithm_findings``: ``algorithms`` holds exactly one non-blank algorithm;
- ``leeway_findings``: ``leeway_seconds`` is a whole number inside the policy's range;
- ``audience_findings``: ``audience`` is the policy's API audience;
- ``discovery_findings``: ``issuer`` and ``jwks_url`` equal the live discovery document's
  ``issuer`` and ``jwks_uri``, and the one algorithm is one the issuer declares.

``python -m tests.security.auth_config`` (``poe auth-config``) prints all of them.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

import httpx

from api.security.tokens import AuthConfigError, AuthSettings, load_auth_settings
from tests.runtime_config import host_port
from tests.security import policy

TASK_ROOT = Path(__file__).resolve().parents[2]
AUTH_CONFIG_PATH = TASK_ROOT / "config/auth.yaml"
DISCOVERY_PATH = "/.well-known/openid-configuration"
ISSUER_DEFAULT_HOST_PORT = 8180


@dataclass(frozen=True)
class Discovery:
    """Hold the three values of the discovery document the checks compare against."""

    issuer: str
    jwks_uri: str
    algorithms: tuple[str, ...]


def discovery_url(root: Path = TASK_ROOT) -> str:
    """Return the discovery document's URL on the host, honouring the port override."""
    port = host_port("COLDLINE_ISSUER_HOST_PORT", ISSUER_DEFAULT_HOST_PORT, root=root)
    return f"http://localhost:{port}{DISCOVERY_PATH}"


def fetch_discovery(url: str | None = None) -> Discovery:
    """Fetch the live discovery document, or raise ``RuntimeError`` saying why it could not."""
    target = discovery_url() if url is None else url
    try:
        response = httpx.get(target, timeout=5.0)
        response.raise_for_status()
        document = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise RuntimeError(
            f"the issuer's discovery document at {target} could not be read ({exc}); "
            "is the stack running (`poe start`)?"
        ) from exc
    if not isinstance(document, dict):
        raise RuntimeError(f"the discovery document at {target} is not a JSON object")
    issuer = document.get("issuer")
    jwks_uri = document.get("jwks_uri")
    declared = document.get("id_token_signing_alg_values_supported")
    if not isinstance(issuer, str) or not isinstance(jwks_uri, str):
        raise RuntimeError(f"the discovery document at {target} names no issuer or jwks_uri")
    if not isinstance(declared, list):
        raise RuntimeError(f"the discovery document at {target} declares no signing algorithms")
    return Discovery(
        issuer=issuer, jwks_uri=jwks_uri, algorithms=tuple(str(alg) for alg in declared)
    )


def algorithm_findings(settings: AuthSettings) -> list[str]:
    """Return why ``algorithms`` is not exactly one pinned algorithm."""
    algorithms = [name for name in settings.algorithms if isinstance(name, str) and name.strip()]
    if len(settings.algorithms) != 1 or len(algorithms) != 1:
        return [
            "algorithms must be a list holding exactly one algorithm, the one the key set "
            f"declares; found {settings.algorithms!r}"
        ]
    return []


def leeway_findings(settings: AuthSettings, low: int, high: int) -> list[str]:
    """Return why ``leeway_seconds`` is not a whole number inside the policy's range."""
    leeway = settings.leeway_seconds
    if leeway is None:
        return ["leeway_seconds is blank; set a whole number inside the policy's range"]
    if not low <= leeway <= high:
        return [
            f"leeway_seconds is {leeway}, outside the range {low} to {high} that "
            "docs/security/access-policy.md allows"
        ]
    return []


def audience_findings(settings: AuthSettings, expected: str) -> list[str]:
    """Return why ``audience`` is not the policy's API audience."""
    if not settings.audience.strip():
        return ["audience is blank; take it from docs/security/access-policy.md"]
    if settings.audience != expected:
        return [
            f"audience is {settings.audience!r}; docs/security/access-policy.md names the "
            "API audience, which is the API a token is for, not the party that signed it"
        ]
    return []


def discovery_findings(settings: AuthSettings, discovery: Discovery) -> list[str]:
    """Return why ``issuer``, ``jwks_url``, or the algorithm disagree with the live issuer."""
    findings: list[str] = []
    if settings.issuer != discovery.issuer:
        findings.append(
            f"issuer is {settings.issuer!r}; the discovery document's issuer is "
            f"{discovery.issuer!r}"
        )
    if settings.jwks_url != discovery.jwks_uri:
        findings.append(
            f"jwks_url is {settings.jwks_url!r}; the discovery document's jwks_uri is "
            f"{discovery.jwks_uri!r}"
        )
    declared = set(discovery.algorithms)
    unknown = [name for name in settings.algorithms if name not in declared]
    if unknown:
        findings.append(
            f"algorithms names {unknown}; the issuer's key set declares {sorted(declared)}"
        )
    return findings


def all_findings(settings: AuthSettings, discovery: Discovery | None) -> dict[str, list[str]]:
    """Return every row's findings, keyed by row; the discovery row only when it was fetched."""
    low, high = policy.leeway_range()
    rows = {
        "algorithm": algorithm_findings(settings),
        "leeway": leeway_findings(settings, low, high),
        "audience": audience_findings(settings, policy.audience()),
    }
    if discovery is not None:
        rows["discovery"] = discovery_findings(settings, discovery)
    return rows


def main() -> int:
    """Print every finding for config/auth.yaml; exit 1 when there is one."""
    try:
        settings = load_auth_settings(AUTH_CONFIG_PATH)
    except AuthConfigError as exc:
        print(f"auth-config failed: {exc}", file=sys.stderr)
        return 1
    try:
        discovery: Discovery | None = fetch_discovery()
    except RuntimeError as exc:
        print(f"auth-config: {exc}", file=sys.stderr)
        discovery = None
    rows = all_findings(settings, discovery)
    findings = [f"{row}: {finding}" for row, items in rows.items() for finding in items]
    if findings or discovery is None:
        for finding in findings:
            print(f"- {finding}", file=sys.stderr)
        if discovery is None:
            print("- discovery: not compared; the issuer did not answer", file=sys.stderr)
        return 1
    print(
        "config/auth.yaml agrees with docs/security/access-policy.md and the issuer's "
        "discovery document."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
