"""Coldline.

===================

File:              tests/unit/adapters/test_provider_keys.py
Component:         Unit tests — Provider key authentication
Purpose:           Prove the emulator's key check accepts exactly the current version, refuses an
                    earlier version and an unknown value with a reason that names no value, and
                    records version ids and fingerprints only.
Interacts With:    src/adapters/model/provider_keys.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          A provider that checks the key it is given, version ids as evidence
Tools:             Python 3.12, pytest
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from adapters.model.provider_keys import (
    ACCEPTED,
    REJECTED,
    AuthenticationOutcome,
    FileAuthenticationRecord,
    MemoryAuthenticationRecord,
    ProviderKeyRejected,
    SecretStoreKeyAuthenticator,
)
from adapters.secrets.localstack import CURRENT_STAGE, SecretUnavailable, SecretVersion, fingerprint
from domain.errors import TerminalProviderError

NAME = "coldline/worker/model-provider-key"
NOW = datetime(2026, 10, 5, 12, 0, tzinfo=UTC)


class FakeStore:
    """A versioned store: (id, value) pairs, oldest first, the last one current."""

    def __init__(self, pairs: list[tuple[str, str]]) -> None:
        """Keep the pairs."""
        self.pairs = list(pairs)
        self.reads = 0

    def _version(self, index: int) -> SecretVersion:
        version_id, value = self.pairs[index]
        stages = (CURRENT_STAGE,) if index == len(self.pairs) - 1 else ()
        return SecretVersion(version_id, fingerprint(value), stages)

    async def current_value(self, name: str) -> tuple[SecretVersion, str]:
        """Stand in for `current_value`."""
        self.reads += 1
        return self._version(len(self.pairs) - 1), self.pairs[-1][1]

    async def versions(self, name: str) -> list[SecretVersion]:
        """Stand in for `versions`."""
        return [self._version(index) for index in range(len(self.pairs))]

    async def value_of(self, name: str, version_id: str) -> str:
        """Stand in for `value_of`."""
        return next(value for identity, value in self.pairs if identity == version_id)


class DownStore(FakeStore):
    """A store that does not answer."""

    async def current_value(self, name: str) -> tuple[SecretVersion, str]:
        """Stand in for `current_value`."""
        raise SecretUnavailable("the secret store is unreachable")


async def test_the_current_version_is_accepted_and_recorded_by_id_and_fingerprint() -> None:
    """Accepting returns the current version id; the record holds the id, never the value."""
    store = FakeStore([("v1", "first-value"), ("v2", "second-value")])
    record = MemoryAuthenticationRecord()
    authenticator = SecretStoreKeyAuthenticator(store, name=NAME, record=record, clock=lambda: NOW)

    assert await authenticator.authenticate("second-value") == "v2"

    last = record.last_accepted()
    assert last is not None and last.accepted and last.version_id == "v2"
    assert last.fingerprint == fingerprint("second-value")
    assert last.at == NOW.isoformat(timespec="seconds")
    assert "second-value" not in json.dumps(last.__dict__)


async def test_an_earlier_version_is_refused_naming_its_version_and_no_value() -> None:
    """A replaced key is refused as terminal; the reason names the version it was."""
    store = FakeStore([("v1", "first-value"), ("v2", "second-value")])
    record = MemoryAuthenticationRecord()
    authenticator = SecretStoreKeyAuthenticator(store, name=NAME, record=record)

    with pytest.raises(ProviderKeyRejected, match="version v1, which was replaced") as excinfo:
        await authenticator.authenticate("first-value")

    assert isinstance(excinfo.value, TerminalProviderError)
    assert "first-value" not in str(excinfo.value)
    attempt = record.last_attempt()
    assert attempt is not None and attempt.outcome == REJECTED and attempt.version_id == "v1"
    assert record.last_accepted() is None


async def test_an_unknown_value_is_refused_as_matching_no_version() -> None:
    """A value no version holds is refused with that reason and recorded without a version."""
    store = FakeStore([("v1", "first-value")])
    record = MemoryAuthenticationRecord()
    authenticator = SecretStoreKeyAuthenticator(store, name=NAME, record=record)

    with pytest.raises(ProviderKeyRejected, match="matches no version"):
        await authenticator.authenticate("stranger")

    attempt = record.last_attempt()
    assert attempt is not None and attempt.version_id is None and not attempt.accepted


async def test_every_authentication_reads_the_store_again() -> None:
    """No cache: a replacement between two requests is seen by the second."""
    store = FakeStore([("v1", "first-value")])
    authenticator = SecretStoreKeyAuthenticator(store, name=NAME)

    assert await authenticator.authenticate("first-value") == "v1"
    store.pairs.append(("v2", "second-value"))
    assert await authenticator.authenticate("second-value") == "v2"
    with pytest.raises(ProviderKeyRejected):
        await authenticator.authenticate("first-value")
    assert store.reads == 3


async def test_a_store_that_does_not_answer_is_a_terminal_failure_not_an_acceptance() -> None:
    """When the store is down the key cannot be checked: terminal, with no value in the message."""
    authenticator = SecretStoreKeyAuthenticator(DownStore([("v1", "x")]), name=NAME)

    with pytest.raises(TerminalProviderError, match="secret store did not answer") as excinfo:
        await authenticator.authenticate("x")
    assert not isinstance(excinfo.value, ProviderKeyRejected)


def test_the_file_record_keeps_the_last_attempt_and_the_last_accepted(tmp_path: Path) -> None:
    """The file holds both, survives a reread, and a rejection does not overwrite the acceptance."""
    record = FileAuthenticationRecord(tmp_path / "auth" / "record.json")
    assert record.last_attempt() is None and record.last_accepted() is None

    accepted = AuthenticationOutcome(ACCEPTED, "v1", "abc", "2026-10-05T12:00:00+00:00", "current")
    rejected = AuthenticationOutcome(REJECTED, "v1", "abc", "2026-10-05T12:01:00+00:00", "replaced")
    record.record(accepted)
    record.record(rejected)

    reread = FileAuthenticationRecord(record.path)
    assert reread.last_attempt() == rejected
    assert reread.last_accepted() == accepted
    document = json.loads(record.path.read_text(encoding="utf-8"))
    assert set(document) == {"last_attempt", "last_accepted"}


def test_a_damaged_record_file_reads_as_empty(tmp_path: Path) -> None:
    """A file that is not the record's JSON is treated as no record, not a crash."""
    path = tmp_path / "record.json"
    path.write_text("{not json", encoding="utf-8")
    record = FileAuthenticationRecord(path)

    assert record.last_attempt() is None and record.last_accepted() is None
    # The rewritten file is read through a new instance, as a fresh worker process would
    # read it; the record keeps no cache, so the instance above reads it the same way.
    path.write_text(json.dumps({"last_attempt": {"outcome": "accepted"}}), encoding="utf-8")
    reread = FileAuthenticationRecord(path)
    assert reread.last_attempt() is None, "an outcome missing its fields is no outcome"
    assert record.last_attempt() is None
