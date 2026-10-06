"""Coldline.

===================

File:              src/api/security/tokens.py
Component:         API — Token verification
Purpose:           Verify a bearer token against the issuer, audience, key set, and leeway in
                    config/auth.yaml.
Interacts With:    config/auth.yaml, the development issuer's JWKS, api.security.access,
                    src/api/bootstrap.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.2
Concepts:          OIDC discovery, JWKS, pinned algorithms, issuer and audience, clock leeway
Tools:             Python 3.12, PyJWT, cryptography, Pydantic, PyYAML

Supplied and settled: configure it through ``config/auth.yaml`` only. ``TokenVerifier``
reads that file's five values and checks a token in this order:

1. the token's ``alg`` is in the configured ``algorithms`` list, and its signature
   verifies against the key the issuer publishes at ``jwks_url`` under the token's
   ``kid`` (the signature check is PyJWT's, with the algorithm list pinned);
2. the ``iss`` claim equals the configured issuer;
3. the ``aud`` claim names the configured audience;
4. the ``exp`` claim, plus ``leeway_seconds``, is still in the future: a token is valid
   strictly before ``exp + leeway`` and expired at that instant; the time claims
   (``exp``, and ``iat`` and ``nbf`` when present) must be finite numbers inside the
   representable range, however large the integer the token carries, and ``nbf`` must
   not lie beyond the leeway in the future.

Every refusal is a ``TokenError`` whose ``reason`` names the failed claim or the
signature; ``poe token-check`` prints it after ``rejected:``. A token that passes yields a
``Principal``: the subject, the role, and the token's scopes. Who may do what is not
decided here; that is ``api.security.access``.

The key set is fetched lazily, once per process, and refetched once when a token names an
unknown ``kid``. Inside the Compose network the host port in ``jwks_url`` does not exist,
so the API composes the verifier with ``jwks_origin`` set to the issuer's in-network
origin; the path is kept, so a wrong ``jwks_url`` path still fails there too. See
``docs/fidelity/TokenIssuer.md`` for what this development issuer does and does not prove.
"""

from __future__ import annotations

import json
import math
import time
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import jwt
import yaml
from jwt.exceptions import (
    DecodeError,
    InvalidAlgorithmError,
    InvalidSignatureError,
    MissingRequiredClaimError,
    PyJWKError,
    PyJWTError,
)
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

# The claims a token must carry before its values are even compared. A token without
# one of them is refused by name, not treated as a token with an empty value.
REQUIRED_CLAIMS = ("iss", "sub", "aud", "exp")
FETCH_TIMEOUT_SECONDS = 5.0
CONFIG_NAME = "config/auth.yaml"


class AuthConfigError(ValueError):
    """Report that config/auth.yaml cannot be read or does not have the published shape."""


class TokenError(Exception):
    """Report one reason a token is not accepted, in the words `poe token-check` prints."""

    def __init__(self, reason: str) -> None:
        """Keep the reason as an attribute so callers can print it without the class name."""
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Principal:
    """Describe a verified caller: who they are, which role they hold, and their token's scopes."""

    subject: str
    role: str
    scopes: frozenset[str]


class AuthSettings(BaseModel):
    """Hold the five values of config/auth.yaml.

    Blank values are allowed here on purpose: the fresh starter ships them blank and the
    API must still start. ``incomplete_fields`` names what is still blank, and the
    verifier refuses every token until nothing is.
    """

    model_config = ConfigDict(extra="forbid")

    issuer: str = ""
    audience: str = ""
    jwks_url: str = ""
    algorithms: list[str] = Field(default_factory=list)
    leeway_seconds: int | None = None

    @field_validator("issuer", "audience", "jwks_url", mode="before")
    @classmethod
    def _blank_string(cls, value: object) -> object:
        """Read a YAML null as a blank value rather than a type error."""
        return "" if value is None else value

    @field_validator("algorithms", mode="before")
    @classmethod
    def _blank_list(cls, value: object) -> object:
        """Read a YAML null as an empty list rather than a type error."""
        return [] if value is None else value

    def incomplete_fields(self) -> list[str]:
        """Return the names of the values still blank, in the file's order."""
        missing: list[str] = []
        if not self.issuer.strip():
            missing.append("issuer")
        if not self.audience.strip():
            missing.append("audience")
        if not self.jwks_url.strip():
            missing.append("jwks_url")
        if not self.algorithms:
            missing.append("algorithms")
        if self.leeway_seconds is None:
            missing.append("leeway_seconds")
        return missing


def load_auth_settings(path: Path) -> AuthSettings:
    """Read config/auth.yaml into ``AuthSettings``, or raise ``AuthConfigError`` with the defect."""
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise AuthConfigError(f"{CONFIG_NAME} could not be read: {exc}") from exc
    if document is None:
        document = {}
    if not isinstance(document, dict):
        raise AuthConfigError(f"{CONFIG_NAME} must be one mapping of the five published keys")
    try:
        return AuthSettings.model_validate(document)
    except ValidationError as exc:
        first = exc.errors()[0]
        location = ".".join(str(part) for part in first["loc"]) or CONFIG_NAME
        raise AuthConfigError(f"{CONFIG_NAME}: {location}: {first['msg']}") from exc


def _fetch_url(url: str) -> bytes:
    """Fetch one http(s) URL's body with a bounded timeout."""
    if urlsplit(url).scheme not in {"http", "https"}:
        raise ValueError(f"jwks_url must be an http or https URL, got {url!r}")
    with urllib.request.urlopen(url, timeout=FETCH_TIMEOUT_SECONDS) as response:
        return bytes(response.read())


def _with_origin(url: str, origin: str) -> str:
    """Return ``url`` with its scheme and host:port replaced by ``origin``, keeping the path."""
    target = urlsplit(origin)
    if not target.scheme or not target.netloc:
        raise AuthConfigError(f"jwks origin must be a scheme and host, got {origin!r}")
    source = urlsplit(url)
    return urlunsplit((target.scheme, target.netloc, source.path, source.query, ""))


class TokenVerifier:
    """Verify bearer tokens against the issuer, audience, key set, and leeway configured."""

    def __init__(
        self,
        settings: AuthSettings,
        *,
        jwks_origin: str | None = None,
        fetch: Callable[[str], bytes] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        """Bind the verifier to its settings, an optional in-network key-set origin, and a fetch."""
        self._settings = settings
        self._fetch = _fetch_url if fetch is None else fetch
        self._clock = clock
        self._jwks_url = (
            _with_origin(settings.jwks_url, jwks_origin)
            if jwks_origin and settings.jwks_url
            else settings.jwks_url
        )
        self._keys: dict[str, jwt.PyJWK] | None = None

    @classmethod
    def from_config(
        cls,
        path: Path,
        *,
        jwks_origin: str | None = None,
        fetch: Callable[[str], bytes] | None = None,
    ) -> TokenVerifier:
        """Build a verifier from config/auth.yaml at ``path``."""
        return cls(load_auth_settings(path), jwks_origin=jwks_origin, fetch=fetch)

    @property
    def settings(self) -> AuthSettings:
        """Return the configured values."""
        return self._settings

    @property
    def jwks_url(self) -> str:
        """Return the URL the key set is actually fetched from, after any origin mapping."""
        return self._jwks_url

    def verify(self, token: str) -> Principal:
        """Return the token's principal, or raise ``TokenError`` with the first failed check."""
        missing = self._settings.incomplete_fields()
        if missing:
            raise TokenError(f"{CONFIG_NAME} is incomplete: {', '.join(missing)} must be set")
        try:
            header = jwt.get_unverified_header(token)
        except PyJWTError as exc:
            raise TokenError("token is malformed: its header could not be decoded") from exc
        algorithm = header.get("alg")
        if algorithm not in self._settings.algorithms:
            raise TokenError(
                f"algorithm {algorithm!r} is not in the pinned list {self._settings.algorithms}"
            )
        key = self._key_for(header.get("kid"))
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                key=key.key,
                algorithms=list(self._settings.algorithms),
                options={
                    "verify_signature": True,
                    "require": list(REQUIRED_CLAIMS),
                    # The claims are compared below, in the documented order, so each
                    # refusal names the claim that failed.
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                    "verify_aud": False,
                    "verify_iss": False,
                    "verify_sub": False,
                    "verify_jti": False,
                },
            )
        except InvalidSignatureError as exc:
            raise TokenError("signature does not verify against the issuer's key set") from exc
        except MissingRequiredClaimError as exc:
            raise TokenError(f"missing claim: {exc.claim}") from exc
        except InvalidAlgorithmError as exc:
            raise TokenError(f"algorithm {algorithm!r} is not in the pinned list") from exc
        except DecodeError as exc:
            raise TokenError("token is malformed: its payload could not be decoded") from exc
        except PyJWTError as exc:
            raise TokenError(f"token could not be verified: {exc}") from exc
        self._check_issuer(claims)
        self._check_audience(claims)
        self._check_expiry(claims)
        return _principal(claims)

    def _check_issuer(self, claims: dict[str, Any]) -> None:
        """Refuse a token another issuer signed, whatever else it says."""
        issuer = claims.get("iss")
        if issuer != self._settings.issuer:
            raise TokenError(f"issuer claim {issuer!r} does not match the configured issuer")

    def _check_audience(self, claims: dict[str, Any]) -> None:
        """Refuse a token issued for another API (``aud`` may be one name or a list)."""
        audience = claims.get("aud")
        audiences = [audience] if isinstance(audience, str) else audience
        if not isinstance(audiences, list) or not all(isinstance(name, str) for name in audiences):
            raise TokenError("audience claim is not a string or a list of strings")
        if self._settings.audience not in audiences:
            raise TokenError(f"audience claim {audience!r} does not name this API's audience")

    def _check_expiry(self, claims: dict[str, Any]) -> None:
        """Refuse a token at or after ``exp`` plus the leeway.

        The boundary is exclusive, as RFC 7519 reads ``exp``: the current time must be
        before the expiration time, so a token is accepted one instant before
        ``exp + leeway`` and refused at that instant, with a zero leeway at ``exp`` itself.
        Every time claim is first required to be a finite number the clock can represent,
        so a non-finite or out-of-range value is a refusal with a reason, never a
        comparison that silently passes or a conversion error that becomes a 500. A
        ``nbf`` further in the future than the leeway allows is refused too.
        """
        now = self._clock()
        leeway = self._settings.leeway_seconds or 0
        expiry = _time_claim(claims, "exp")
        if "iat" in claims:
            _time_claim(claims, "iat")
        if "nbf" in claims:
            not_before = _time_claim(claims, "nbf")
            if not_before > now + leeway:
                raise TokenError(
                    f"token is not valid before {_iso(not_before, 'nbf')}, beyond the "
                    f"{leeway}s leeway"
                )
        if expiry <= now - leeway:
            raise TokenError(f"token expired at {_iso(expiry, 'exp')}, beyond the {leeway}s leeway")

    def _key_for(self, kid: object) -> jwt.PyJWK:
        """Return the published key a token names, refetching the key set once if needed."""
        keys = self._load_keys(refresh=False)
        if kid is None:
            if len(keys) == 1:
                return next(iter(keys.values()))
            raise TokenError("token names no key id (kid) and the key set holds several keys")
        if not isinstance(kid, str):
            raise TokenError("token's key id (kid) is not a string")
        if kid not in keys:
            keys = self._load_keys(refresh=True)
        if kid not in keys:
            raise TokenError(f"key id {kid!r} is not in the issuer's key set")
        return keys[kid]

    def _load_keys(self, *, refresh: bool) -> dict[str, jwt.PyJWK]:
        """Fetch and parse the key set, keeping it for the process unless a refresh is asked."""
        if self._keys is not None and not refresh:
            return self._keys
        try:
            raw = self._fetch(self._jwks_url)
        except (OSError, ValueError) as exc:
            raise TokenError(
                f"the issuer's key set at {self._jwks_url} could not be fetched: {exc}"
            ) from exc
        try:
            document = json.loads(raw)
        except ValueError as exc:
            raise TokenError(f"the key set at {self._jwks_url} is not JSON") from exc
        entries = document.get("keys") if isinstance(document, dict) else None
        if not isinstance(entries, list) or not entries:
            raise TokenError(f"the key set at {self._jwks_url} declares no keys")
        parsed: dict[str, jwt.PyJWK] = {}
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("kid"), str):
                raise TokenError("the key set holds a key without a string kid")
            try:
                parsed[entry["kid"]] = jwt.PyJWK.from_dict(entry)
            except (PyJWKError, PyJWTError, ValueError) as exc:
                raise TokenError(
                    f"key {entry['kid']!r} in the key set could not be loaded"
                ) from exc
        self._keys = parsed
        return parsed


def _iso(timestamp: float, name: str) -> str:
    """Render one time claim as an ISO instant, or refuse a value the clock cannot represent."""
    try:
        return datetime.fromtimestamp(timestamp, UTC).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError) as exc:
        raise TokenError(f"{name} claim {timestamp!r} is outside the representable range") from exc


def _time_claim(claims: dict[str, Any], name: str) -> float:
    """Return one time claim as a finite, representable number of seconds, or refuse it.

    The conversion to ``float`` comes first and inside its own handler: a JSON integer can
    be arbitrarily large, and ``math.isfinite`` on one too large for a float raises
    ``OverflowError`` instead of answering. Then the value must be finite, then one
    ``datetime.fromtimestamp`` can represent; the converted value is what the comparisons
    use.
    """
    value = claims.get(name)
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise TokenError(f"{name} claim is not a number")
    try:
        number = float(value)
    except OverflowError as exc:
        raise TokenError(
            f"{name} claim is outside the representable range: too large for a timestamp"
        ) from exc
    if not math.isfinite(number):
        raise TokenError(f"{name} claim is not a finite number")
    _iso(number, name)
    return number


def _principal(claims: dict[str, Any]) -> Principal:
    """Build the verified caller from the token's subject, role, and scope claims."""
    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject:
        raise TokenError("subject claim (sub) is not a string")
    role = claims.get("role")
    if not isinstance(role, str) or not role:
        raise TokenError("role claim is missing or not a string")
    scope = claims.get("scope", "")
    if not isinstance(scope, str):
        raise TokenError("scope claim is not a space-separated string")
    return Principal(subject=subject, role=role, scopes=frozenset(scope.split()))
