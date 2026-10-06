"""Coldline.

===================

File:              src/adapters/model/provider_keys.py
Component:         Adapter — Provider key authentication
Purpose:           Make the model emulator accept only the current version of the provider key,
                    and record which version it authenticated, never the value.
Interacts With:    src/adapters/model/deterministic.py, src/adapters/secrets/localstack.py,
                    src/worker/bootstrap.py, src/worker/provider_auth.py,
                    tests/security/secret_tools.py, docs/fidelity/SecretProvider.md
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          A provider that checks the key it is given, version ids as evidence,
                    terminal refusal
Tools:             Python 3.12, hmac, json

A hosted provider authenticates every request by the key the client presents. From Task
4.5 the deterministic emulator does the same: ``SecretStoreKeyAuthenticator`` compares the
presented key with the **current** version of the provider key in the local secret store
and refuses anything else, an earlier version included, with ``ProviderKeyRejected``, a
``TerminalProviderError`` (the resilient wrapper does not retry it, and the worker records
the exception ``FAILED`` with ``model_provider_terminal_failure``). What the emulator
learned is written to an ``AuthenticationRecord``: the outcome, the version id and the
fingerprint, never the value. ``poe provider-auth-check`` prints that record from inside
the worker container (``src/worker/provider_auth.py``).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from adapters.secrets.localstack import (
    SecretUnavailable,
    SecretVersion,
    fingerprint,
    values_match,
)
from domain.errors import TerminalProviderError

ACCEPTED = "accepted"
REJECTED = "rejected"


class VersionedSecretStore(Protocol):
    """What the authenticator needs of the secret store: the current value and the versions."""

    async def current_value(self, name: str) -> tuple[SecretVersion, str]:
        """Return the current version and its value."""
        ...

    async def versions(self, name: str) -> list[SecretVersion]:
        """Return every version the store still holds."""
        ...

    async def value_of(self, name: str, version_id: str) -> str:
        """Return one version's value."""
        ...


class ProviderKeyRejected(TerminalProviderError):
    """Report that the presented key is not the current version of the provider key."""


@dataclass(frozen=True)
class AuthenticationOutcome:
    """What one authentication left behind: never the key, only its version and fingerprint.

    ``version_id`` is the version the presented key matched (the current one when
    accepted, an earlier one when the key was replaced since), or None when it matched no
    version at all.
    """

    outcome: str
    version_id: str | None
    fingerprint: str
    at: str
    reason: str

    @property
    def accepted(self) -> bool:
        """Return whether the provider accepted the key."""
        return self.outcome == ACCEPTED


class AuthenticationRecord(Protocol):
    """Keep the last authentication, and the last accepted one, for `poe provider-auth-check`."""

    def record(self, outcome: AuthenticationOutcome) -> None:
        """Keep one outcome as the last attempt, and as the last accepted one when it was."""
        ...

    def last_attempt(self) -> AuthenticationOutcome | None:
        """Return the most recent attempt, or None when the provider has seen none."""
        ...

    def last_accepted(self) -> AuthenticationOutcome | None:
        """Return the most recent accepted authentication, or None."""
        ...


class KeyAuthenticator(Protocol):
    """Decide whether a presented key is the provider's current key; return its version id."""

    async def authenticate(self, presented: str) -> str:
        """Return the version id the key matched, or raise ``ProviderKeyRejected``."""
        ...


def _outcome_from(document: object) -> AuthenticationOutcome | None:
    """Rebuild one outcome from its JSON document, or None when the document is not one."""
    if not isinstance(document, dict):
        return None
    try:
        return AuthenticationOutcome(
            outcome=str(document["outcome"]),
            version_id=document.get("version_id"),
            fingerprint=str(document["fingerprint"]),
            at=str(document["at"]),
            reason=str(document.get("reason", "")),
        )
    except KeyError:
        return None


class MemoryAuthenticationRecord:
    """Keep the outcomes in memory, for the in-process harness and the unit tests."""

    def __init__(self) -> None:
        """Start with no attempt."""
        self.attempts: list[AuthenticationOutcome] = []

    def record(self, outcome: AuthenticationOutcome) -> None:
        """Append one outcome."""
        self.attempts.append(outcome)

    def last_attempt(self) -> AuthenticationOutcome | None:
        """Return the last outcome, or None."""
        return self.attempts[-1] if self.attempts else None

    def last_accepted(self) -> AuthenticationOutcome | None:
        """Return the last accepted outcome, or None."""
        accepted = [item for item in self.attempts if item.accepted]
        return accepted[-1] if accepted else None


class FileAuthenticationRecord:
    """Keep the last attempt and the last accepted authentication in one JSON file.

    The worker container points this at a file in the worker user's home
    (``COLDLINE_PROVIDER_AUTH_RECORD`` in ``compose.yaml``); it lives and dies with the
    container, like the model request records.
    """

    def __init__(self, path: Path) -> None:
        """Bind the record to its file; it is created on the first authentication."""
        self._path = path

    @property
    def path(self) -> Path:
        """Return the file the record is written to."""
        return self._path

    def _load(self) -> dict[str, Any]:
        if not self._path.is_file():
            return {}
        try:
            loaded = json.loads(self._path.read_text(encoding="utf-8"))
        except ValueError:
            return {}
        return dict(loaded) if isinstance(loaded, dict) else {}

    def record(self, outcome: AuthenticationOutcome) -> None:
        """Write the outcome as the last attempt, and as the last accepted one when it was."""
        document = self._load()
        document["last_attempt"] = asdict(outcome)
        if outcome.accepted:
            document["last_accepted"] = asdict(outcome)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(document, indent=2, sort_keys=True), encoding="utf-8")

    def last_attempt(self) -> AuthenticationOutcome | None:
        """Return the last attempt the file holds, or None."""
        return _outcome_from(self._load().get("last_attempt"))

    def last_accepted(self) -> AuthenticationOutcome | None:
        """Return the last accepted authentication the file holds, or None."""
        return _outcome_from(self._load().get("last_accepted"))


class SecretStoreKeyAuthenticator:
    """Accept exactly the current version of the provider key held in the secret store.

    The provider's registry of valid keys is the secret store's current version: on every
    authentication the current value is read from the store, so a replacement takes
    effect at once, with no restart of anything. A key that matches an earlier version is
    refused with a reason that names that version's id; a key that matches no version is
    refused as unknown. Every attempt is written to the record, when one is composed.
    """

    def __init__(
        self,
        store: VersionedSecretStore,
        *,
        name: str,
        record: AuthenticationRecord | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Bind the authenticator to the store, the secret's name, and an optional record."""
        self._store = store
        self._name = name
        self._record = record
        self._clock = clock or (lambda: datetime.now(UTC))

    @property
    def record(self) -> AuthenticationRecord | None:
        """Return the record the outcomes are written to, if one is composed."""
        return self._record

    async def authenticate(self, presented: str) -> str:
        """Return the current version's id when ``presented`` is its value; raise otherwise."""
        try:
            current, value = await self._store.current_value(self._name)
        except SecretUnavailable as exc:
            raise TerminalProviderError(
                "the model provider could not check the presented key: the secret store did "
                "not answer"
            ) from exc
        presented_fingerprint = fingerprint(presented)
        if values_match(presented, value):
            self._write(ACCEPTED, current.version_id, presented_fingerprint, "current version")
            return current.version_id
        matched = await self._matching_version(presented)
        if matched is None:
            reason = "the presented key matches no version of the provider key"
        else:
            reason = f"the presented key is version {matched}, which was replaced"
        self._write(REJECTED, matched, presented_fingerprint, reason)
        raise ProviderKeyRejected(
            f"the model provider rejected the presented key: it is not the current version "
            f"({reason})"
        )

    async def _matching_version(self, presented: str) -> str | None:
        """Return the id of the version whose value is ``presented``, or None."""
        try:
            for version in await self._store.versions(self._name):
                stored = await self._store.value_of(self._name, version.version_id)
                if values_match(presented, stored):
                    return version.version_id
        except SecretUnavailable:
            return None
        return None

    def _write(self, outcome: str, version_id: str | None, digest: str, reason: str) -> None:
        if self._record is None:
            return
        self._record.record(
            AuthenticationOutcome(
                outcome=outcome,
                version_id=version_id,
                fingerprint=digest,
                at=self._clock().isoformat(timespec="seconds"),
                reason=reason,
            )
        )


__all__ = [
    "ACCEPTED",
    "REJECTED",
    "AuthenticationOutcome",
    "AuthenticationRecord",
    "FileAuthenticationRecord",
    "KeyAuthenticator",
    "MemoryAuthenticationRecord",
    "ProviderKeyRejected",
    "SecretStoreKeyAuthenticator",
    "VersionedSecretStore",
]
