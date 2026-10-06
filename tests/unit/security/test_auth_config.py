"""Coldline.

===================

File:              tests/unit/security/test_auth_config.py
Component:         Unit tests — Verification settings check and policy reader
Purpose:           Prove the config findings and the policy rows they read, without an issuer.
Interacts With:    tests/security/auth_config.py, tests/security/policy.py,
                    docs/security/access-policy.md
Sprint/Task:       Sprint 4 — Project 4 / Task 4.2
Concepts:          Policy as the source of configuration, pinned algorithm, leeway range
Tools:             Python 3.12, pytest
"""

from __future__ import annotations

from api.security.tokens import AuthSettings
from tests.security import auth_config, policy
from tests.security.fixtures import FIXTURE_NAMES, load_fixtures

DISCOVERY = auth_config.Discovery(
    issuer="https://issuer.coldline.test",
    jwks_uri="http://localhost:8180/.well-known/jwks.json",
    algorithms=("RS256",),
)


def _complete(**overrides: object) -> AuthSettings:
    """Return settings that agree with the policy and the discovery document."""
    values: dict[str, object] = {
        "issuer": DISCOVERY.issuer,
        "audience": policy.audience(),
        "jwks_url": DISCOVERY.jwks_uri,
        "algorithms": ["RS256"],
        "leeway_seconds": 30,
    }
    values.update(overrides)
    return AuthSettings.model_validate(values)


def test_the_policy_names_the_audience_and_a_small_leeway_range() -> None:
    """The two machine-read rows exist and say what the Task relies on."""
    assert policy.audience() == "coldline-api"
    low, high = policy.leeway_range()
    assert low == 0 and 0 < high <= 300


def test_complete_settings_have_no_findings() -> None:
    """Settings copied from the discovery document and the policy pass every row."""
    rows = auth_config.all_findings(_complete(), DISCOVERY)

    assert rows == {"algorithm": [], "leeway": [], "audience": [], "discovery": []}


def test_the_blank_starter_fails_every_row() -> None:
    """A blank config/auth.yaml is named row by row, not as one parse error."""
    rows = auth_config.all_findings(AuthSettings(), DISCOVERY)

    assert all(rows[row] for row in ("algorithm", "leeway", "audience", "discovery")), rows


def test_two_algorithms_or_a_blank_one_fail_the_algorithm_row() -> None:
    """The list must hold exactly one real algorithm name."""
    assert auth_config.algorithm_findings(_complete(algorithms=["RS256", "HS256"]))
    assert auth_config.algorithm_findings(_complete(algorithms=[""]))
    assert auth_config.algorithm_findings(_complete(algorithms=[]))
    assert auth_config.algorithm_findings(_complete()) == []


def test_leeway_outside_the_policy_range_is_named_with_the_range() -> None:
    """A leeway raised until `expired` passes is caught by the policy, not by the token."""
    low, high = policy.leeway_range()

    findings = auth_config.leeway_findings(_complete(leeway_seconds=high + 1), low, high)

    assert len(findings) == 1 and f"{low} to {high}" in findings[0]
    assert auth_config.leeway_findings(_complete(leeway_seconds=low), low, high) == []
    assert auth_config.leeway_findings(_complete(leeway_seconds=high), low, high) == []


def test_the_issuer_url_as_audience_is_the_named_mistake() -> None:
    """The audience row distinguishes the API's name from the party that signed the token."""
    findings = auth_config.audience_findings(_complete(audience=DISCOVERY.issuer), "coldline-api")

    assert len(findings) == 1 and "not the party that signed it" in findings[0]


def test_discovery_findings_compare_issuer_jwks_url_and_the_declared_algorithm() -> None:
    """Each disagreement with the live document is one finding naming both values."""
    drifted = _complete(
        issuer="https://issuer.example.test",
        jwks_url="http://localhost:8180/keys.json",
        algorithms=["ES256"],
    )

    findings = auth_config.discovery_findings(drifted, DISCOVERY)

    assert len(findings) == 3
    assert any("issuer" in finding for finding in findings)
    assert any("jwks_uri" in finding for finding in findings)
    assert any("ES256" in finding for finding in findings)


def test_the_fixture_file_holds_exactly_the_eight_named_tokens() -> None:
    """The committed fixtures and the loader's name table agree."""
    fixtures = load_fixtures()

    assert tuple(fixtures) == FIXTURE_NAMES
    assert all(value.count(".") == 2 for value in fixtures.values())
