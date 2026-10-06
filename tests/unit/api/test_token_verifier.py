"""Coldline.

===================

File:              tests/unit/api/test_token_verifier.py
Component:         Unit tests — Token verifier
Purpose:           Prove the supplied verifier's verdicts and reasons over the committed fixtures
                    and key set.
Interacts With:    src/api/security/tokens.py, infra/issuer/jwks.json,
                    tests/fixtures/tokens/fixtures.yaml
Sprint/Task:       Sprint 4 — Project 4 / Task 4.2
Concepts:          Signature, issuer, audience, expiry, pinned algorithms, origin mapping
Tools:             Python 3.12, pytest

No issuer container: the key set is read from the committed file through the verifier's
``fetch`` hook, which also lets these tests observe which URL the verifier asks for.
"""

from __future__ import annotations

import base64
import functools
import json
from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from api.security.access import STATUS_BY_KIND, AccessDenied, check_access
from api.security.tokens import (
    AuthConfigError,
    AuthSettings,
    TokenError,
    TokenVerifier,
    load_auth_settings,
)
from tests.security.fixtures import FIXTURE_NAMES, INVALID, UNAUTHORIZED, token

TASK_ROOT = Path(__file__).resolve().parents[3]
KEY_SET = TASK_ROOT / "infra/issuer/jwks.json"
ISSUER = "https://issuer.coldline.test"
JWKS_URL = "http://localhost:8180/.well-known/jwks.json"


def _settings(**overrides: object) -> AuthSettings:
    """Return complete settings for the development issuer, with overrides."""
    values: dict[str, object] = {
        "issuer": ISSUER,
        "audience": "coldline-api",
        "jwks_url": JWKS_URL,
        "algorithms": ["RS256"],
        "leeway_seconds": 30,
    }
    values.update(overrides)
    return AuthSettings.model_validate(values)


def _verifier(settings: AuthSettings | None = None, **kwargs: object) -> TokenVerifier:
    """Return a verifier that reads the committed key set instead of fetching it."""
    return TokenVerifier(
        settings or _settings(),
        fetch=lambda url: KEY_SET.read_bytes(),
        **kwargs,  # type: ignore[arg-type]
    )


def test_dispatcher_valid_yields_its_principal() -> None:
    """The one accepted fixture becomes a principal with its subject, role, and scopes."""
    principal = _verifier().verify(token("dispatcher-valid"))

    assert principal.role == "dispatcher"
    assert "exceptions:read" in principal.scopes
    assert principal.subject


@pytest.mark.parametrize("fixture", UNAUTHORIZED)
def test_valid_but_ungranted_fixtures_are_accepted_by_the_verifier(fixture: str) -> None:
    """The verifier identifies callers; what they may do is the access rule's question."""
    principal = _verifier().verify(token(fixture))

    assert principal.subject and principal.role


@pytest.mark.parametrize(
    "fixture,words",
    [
        ("bad-signature", "signature"),
        ("wrong-issuer", "issuer claim"),
        ("wrong-audience", "audience claim"),
        ("expired", "expired"),
    ],
)
def test_each_invalid_fixture_is_refused_with_a_reason_naming_its_defect(
    fixture: str, words: str
) -> None:
    """Every refusal names the failed claim or the signature, which `poe token-check` prints."""
    with pytest.raises(TokenError) as refused:
        _verifier().verify(token(fixture))

    assert words in refused.value.reason


def test_an_algorithm_outside_the_pinned_list_is_refused_before_the_key_is_consulted() -> None:
    """A token naming another algorithm is refused for the algorithm, whatever its signature."""
    fetched: list[str] = []

    def fetch(url: str) -> bytes:
        fetched.append(url)
        return KEY_SET.read_bytes()

    verifier = TokenVerifier(_settings(algorithms=["HS256"]), fetch=fetch)
    with pytest.raises(TokenError, match="not in the pinned list"):
        verifier.verify(token("dispatcher-valid"))

    assert fetched == [], "the key set must not be fetched for a token with the wrong alg"


def test_the_configured_audience_is_compared_not_the_issuer() -> None:
    """Setting the audience to the issuer URL refuses the valid dispatcher token."""
    with pytest.raises(TokenError, match="audience claim"):
        _verifier(_settings(audience=ISSUER)).verify(token("dispatcher-valid"))


def test_leeway_extends_expiry_by_exactly_that_many_seconds_with_an_exclusive_boundary() -> None:
    """A token is accepted strictly before `exp` plus the leeway and refused at that instant.

    RFC 7519 reads `exp` as "the current time must be before the expiration time", so the
    boundary is exclusive: with a 60 s leeway the last accepted instant is `exp + 59.999`,
    and `exp + 60` is expired; with no leeway, `exp` itself is expired.
    """
    expired_at = 1704153600  # the `expired` fixture's exp: 2024-01-02T00:00:00Z

    inside = _verifier(_settings(leeway_seconds=60), clock=lambda: expired_at + 59.999)
    assert inside.verify(token("expired")).role == "dispatcher"

    at_boundary = _verifier(_settings(leeway_seconds=60), clock=lambda: expired_at + 60)
    with pytest.raises(TokenError, match="expired"):
        at_boundary.verify(token("expired"))

    beyond = _verifier(_settings(leeway_seconds=60), clock=lambda: expired_at + 61)
    with pytest.raises(TokenError, match="expired"):
        beyond.verify(token("expired"))

    zero_inside = _verifier(_settings(leeway_seconds=0), clock=lambda: expired_at - 1)
    assert zero_inside.verify(token("expired")).role == "dispatcher"

    zero_at_exp = _verifier(_settings(leeway_seconds=0), clock=lambda: expired_at)
    with pytest.raises(TokenError, match="expired"):
        zero_at_exp.verify(token("expired"))


def test_incomplete_settings_refuse_every_token_naming_the_blank_values() -> None:
    """The starter's blank config/auth.yaml composes, and refuses with the blanks named."""
    verifier = _verifier(AuthSettings())
    with pytest.raises(TokenError) as refused:
        verifier.verify(token("dispatcher-valid"))

    assert "incomplete" in refused.value.reason
    for name in ("issuer", "audience", "jwks_url", "algorithms", "leeway_seconds"):
        assert name in refused.value.reason


def test_jwks_origin_replaces_the_host_and_keeps_the_path() -> None:
    """Inside Compose the origin becomes the issuer's; a wrong path still reaches a wrong path."""
    settings = _settings(jwks_url="http://localhost:8180/.well-known/jwks.json")
    verifier = TokenVerifier(settings, jwks_origin="http://issuer:8180")

    assert verifier.jwks_url == "http://issuer:8180/.well-known/jwks.json"

    wrong_path = _settings(jwks_url="http://localhost:8180/keys.json")
    mapped = TokenVerifier(wrong_path, jwks_origin="http://issuer:8180")
    assert mapped.jwks_url == "http://issuer:8180/keys.json"


def test_the_key_set_is_fetched_once_and_refetched_only_for_an_unknown_kid() -> None:
    """One fetch serves every verification; an unknown kid earns one more, then a refusal."""
    fetched: list[str] = []

    def fetch(url: str) -> bytes:
        fetched.append(url)
        return KEY_SET.read_bytes()

    verifier = TokenVerifier(_settings(), fetch=fetch)
    for name in FIXTURE_NAMES:
        try:
            verifier.verify(token(name))
        except TokenError:
            pass
    assert fetched == [JWKS_URL]

    # A token naming a key id the set does not hold: the header is rewritten properly.
    header, payload, signature = token("dispatcher-valid").split(".")
    decoded = json.loads(base64.urlsafe_b64decode(header + "=" * (-len(header) % 4)))
    decoded["kid"] = "coldline-dev-2027"
    rewritten = base64.urlsafe_b64encode(
        json.dumps(decoded, separators=(",", ":"), sort_keys=True).encode()
    ).rstrip(b"=")
    unknown_kid = f"{rewritten.decode()}.{payload}.{signature}"
    with pytest.raises(TokenError, match="not in the issuer's key set"):
        verifier.verify(unknown_kid)
    assert fetched == [JWKS_URL, JWKS_URL]


def test_an_unreachable_key_set_is_a_refusal_with_the_url_named() -> None:
    """The fetch failure becomes a reason, not a traceback."""

    def fetch(url: str) -> bytes:
        raise OSError("connection refused")

    verifier = TokenVerifier(_settings(), fetch=fetch)
    with pytest.raises(TokenError, match="could not be fetched"):
        verifier.verify(token("dispatcher-valid"))


def test_a_malformed_token_is_refused_as_malformed() -> None:
    """Garbage in the Authorization header is a 401 reason, not an exception."""
    with pytest.raises(TokenError, match="malformed"):
        _verifier().verify("not-a-token")


def test_every_invalid_fixture_is_refused_and_no_other() -> None:
    """The fixture file and the verifier agree on which four tokens are invalid."""
    verifier = _verifier()
    refused = []
    for name in FIXTURE_NAMES:
        try:
            verifier.verify(token(name))
        except TokenError:
            refused.append(name)

    assert refused == list(INVALID)


@functools.lru_cache(maxsize=1)
def _signing_pair() -> tuple[bytes, bytes]:
    """Return a fresh RSA private key (PEM) and the key set that publishes its public half.

    The committed fixtures cannot carry malformed time claims, and the development
    issuer's private key is not in this repository, so these tests sign with a key of
    their own and hand the verifier a key set that declares it.
    """
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public = json.loads(RSAAlgorithm.to_jwk(private.public_key()))
    public.update({"kid": "unit-test", "alg": "RS256", "use": "sig"})
    return pem, json.dumps({"keys": [public]}).encode("utf-8")


def _signed(claims: dict[str, Any]) -> str:
    """Sign ``claims`` as given, bypassing PyJWT's payload normalisation."""
    pem, _ = _signing_pair()
    payload = json.dumps(claims).encode("utf-8")
    return jwt.api_jws.PyJWS().encode(
        payload, key=pem, algorithm="RS256", headers={"kid": "unit-test"}
    )


def _own_key_verifier(**overrides: object) -> TokenVerifier:
    """Return a verifier over the test key set, with a fixed clock at 2026-09-01T00:00:00Z."""
    _, key_set = _signing_pair()
    return TokenVerifier(
        _settings(**overrides), fetch=lambda url: key_set, clock=lambda: 1_787_000_000.0
    )


def _claims(**overrides: object) -> dict[str, Any]:
    """Return a valid dispatcher claim set for the test issuer, with overrides."""
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "sub": "user:unit-01",
        "aud": "coldline-api",
        "exp": 1_787_000_000 + 3600,
        "role": "dispatcher",
        "scope": "exceptions:read",
    }
    claims.update(overrides)
    return claims


def test_a_well_formed_token_from_the_test_key_is_accepted() -> None:
    """The test key set and signer are themselves sound, so the refusals below are the claims'."""
    principal = _own_key_verifier().verify(_signed(_claims()))

    assert principal.role == "dispatcher"


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_a_non_finite_expiry_is_refused_not_compared(value: float) -> None:
    """NaN compares false with everything; the verifier refuses it before comparing."""
    with pytest.raises(TokenError, match="exp claim is not a finite number"):
        _own_key_verifier().verify(_signed(_claims(exp=value)))


@pytest.mark.parametrize("value", [-1e18, 1e19, -62_135_596_801, 253_402_300_800])
def test_an_out_of_range_expiry_is_a_refusal_with_a_reason_not_a_crash(value: float) -> None:
    """A timestamp the clock cannot represent is refused by name, never a conversion error."""
    with pytest.raises(TokenError, match="exp claim .* is outside the representable range"):
        _own_key_verifier().verify(_signed(_claims(exp=value)))


@pytest.mark.parametrize(
    "claim, value, words",
    [
        ("exp", "2099-01-01T00:00:00Z", "exp claim is not a number"),
        ("exp", True, "exp claim is not a number"),
        ("iat", "yesterday", "iat claim is not a number"),
        ("iat", float("nan"), "iat claim is not a finite number"),
        ("nbf", 1e19, "nbf claim .* is outside the representable range"),
        ("nbf", float("inf"), "nbf claim is not a finite number"),
    ],
)
def test_malformed_iat_and_nbf_claims_are_refused_like_exp(
    claim: str, value: object, words: str
) -> None:
    """Every time claim present must be a finite, representable number."""
    with pytest.raises(TokenError, match=words):
        _own_key_verifier().verify(_signed(_claims(**{claim: value})))


@pytest.mark.parametrize("claim", ["exp", "iat", "nbf"])
@pytest.mark.parametrize("sign", [1, -1], ids=["positive", "negative"])
def test_an_oversized_integer_time_claim_is_a_refusal_not_an_overflow(
    claim: str, sign: int
) -> None:
    """A correctly signed `10**400` (or its negative) in a time claim is refused by name.

    JSON integers are unbounded and `math.isfinite` on one too large for a float raises
    `OverflowError`; the verifier converts inside a handler, so the token is a `TokenError`
    the access rule turns into a 401, never a server error.
    """
    oversized = sign * 10**400
    with pytest.raises(TokenError, match=f"{claim} claim is outside the representable range"):
        _own_key_verifier().verify(_signed(_claims(**{claim: oversized})))

    with pytest.raises(AccessDenied) as refused:
        check_access(
            _own_key_verifier(),
            f"Bearer {_signed(_claims(**{claim: oversized}))}",
            role="dispatcher",
            scope="exceptions:read",
        )
    assert refused.value.kind == "unauthenticated", "an oversized time claim is a 401"
    assert STATUS_BY_KIND[refused.value.kind] == 401
    assert "outside the representable range" in refused.value.reason


def test_nbf_is_enforced_with_the_same_leeway_as_exp() -> None:
    """A token not yet valid beyond the leeway is refused; one inside the leeway is accepted."""
    now = 1_787_000_000
    accepted = _own_key_verifier(leeway_seconds=30).verify(_signed(_claims(nbf=now + 30)))
    assert accepted.role == "dispatcher"

    with pytest.raises(TokenError, match="not valid before"):
        _own_key_verifier(leeway_seconds=30).verify(_signed(_claims(nbf=now + 31)))


def test_load_auth_settings_reads_the_blank_starter_and_rejects_a_wrong_shape(
    tmp_path: Path,
) -> None:
    """A blank file loads as incomplete settings; an unknown key or a non-list is a config error.

    The shipped file is read as the student would ship it back: blank on a fresh starter,
    complete after Step 1. Either way it loads; what matters here is that loading never
    raises on blanks and that the two shape errors are named.
    """
    starter = load_auth_settings(TASK_ROOT / "config/auth.yaml")
    assert set(starter.incomplete_fields()) <= {
        "issuer",
        "audience",
        "jwks_url",
        "algorithms",
        "leeway_seconds",
    }

    wrong_key = tmp_path / "auth.yaml"
    wrong_key.write_text("issuer: x\naudiences: y\n", encoding="utf-8")
    with pytest.raises(AuthConfigError, match="audiences"):
        load_auth_settings(wrong_key)

    not_a_list = tmp_path / "auth2.yaml"
    not_a_list.write_text("algorithms: RS256\n", encoding="utf-8")
    with pytest.raises(AuthConfigError, match="algorithms"):
        load_auth_settings(not_a_list)
