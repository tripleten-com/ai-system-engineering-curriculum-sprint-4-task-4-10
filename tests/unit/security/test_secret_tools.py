"""Coldline.

===================

File:              tests/unit/security/test_secret_tools.py
Component:         Unit tests — The secret tools
Purpose:           Prove `poe secret-status`, `poe secret-replace` and `poe secret-check-old` print
                    version ids and fingerprints and never a value, that `replace` generates a
                    key in the supplied provider-key format, that `check-old` hands the previous
                    version to the emulator's key check, and that the host endpoint follows the
                    LocalStack port override.
Interacts With:    tests/security/secret_tools.py, tests/security/seeds.py,
                    src/adapters/model/provider_keys.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          Versions and fingerprints as evidence, never a value on the terminal
Tools:             Python 3.12, pytest
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

import pytest

from adapters.secrets.localstack import (
    CURRENT_STAGE,
    FIRST_VERSION_VALUE,
    PREVIOUS_STAGE,
    SecretStatus,
    SecretVersion,
    fingerprint,
)
from tests.security import secret_tools, seeds

NAME = "coldline/worker/model-provider-key"


class FakeStore:
    """A versioned store the tools can drive: (id, value) pairs, the last current."""

    def __init__(self, pairs: list[tuple[str, str]]) -> None:
        """Keep the pairs."""
        self.pairs = list(pairs)

    def _version(self, index: int) -> SecretVersion:
        version_id, value = self.pairs[index]
        last = len(self.pairs) - 1
        stages: tuple[str, ...] = ()
        if index == last:
            stages = (CURRENT_STAGE,)
        elif index == last - 1:
            stages = (PREVIOUS_STAGE,)
        return SecretVersion(version_id, fingerprint(value), stages)

    async def current_value(self, name: str) -> tuple[SecretVersion, str]:
        """Stand in for `current_value`."""
        return self._version(len(self.pairs) - 1), self.pairs[-1][1]

    async def current_version(self, name: str) -> SecretVersion:
        """Stand in for `current_version`."""
        return self._version(len(self.pairs) - 1)

    async def versions(self, name: str) -> list[SecretVersion]:
        """Stand in for `versions`."""
        return [self._version(index) for index in range(len(self.pairs))]

    async def value_of(self, name: str, version_id: str) -> str:
        """Stand in for `value_of`."""
        return next(value for identity, value in self.pairs if identity == version_id)

    async def status(self, name: str) -> SecretStatus:
        """Stand in for `status`."""
        versions = await self.versions(name)
        previous = next((v for v in versions if PREVIOUS_STAGE in v.stages), None)
        return SecretStatus(name, versions[-1], previous, len(versions))

    async def put_version(self, name: str, value: str) -> SecretVersion:
        """Stand in for `put_version`."""
        self.pairs.append((f"v{len(self.pairs) + 1}", value))
        return await self.current_version(name)


def _lines(store: FakeStore) -> list[str]:
    return secret_tools.status_lines(asyncio.run(store.status(NAME)))


def test_status_prints_ids_fingerprints_and_the_count_and_no_value() -> None:
    """The current and previous versions by id and fingerprint; `none` without a previous one."""
    single = FakeStore([("v1", "first-secret-value")])
    lines = _lines(single)
    assert lines[1] == f"  current version: v1 (fingerprint {fingerprint('first-secret-value')})"
    assert lines[2] == "  previous version: none"
    assert lines[3] == "  versions held: 1"
    assert "first-secret-value" not in "\n".join(lines)

    two = FakeStore([("v1", "first-secret-value"), ("v2", "second-secret-value")])
    lines = _lines(two)
    assert "previous version: v1" in lines[2] and "second-secret-value" not in "\n".join(lines)


def test_replace_stores_a_fresh_value_and_prints_the_new_and_previous_ids() -> None:
    """A new current version with a random value; the lines name ids, never the value."""
    store = FakeStore([("v1", "first-secret-value")])

    created, before = asyncio.run(secret_tools.replace(store, NAME))  # type: ignore[arg-type]

    assert before.version_id == "v1" and created.version_id == "v2"
    new_value = store.pairs[-1][1]
    # Every comparison against the generated value is computed first and asserted as a
    # boolean with a constant message, so a failing assertion renders no value and no line.
    long_and_fresh = len(new_value) >= 32 and new_value != "first-secret-value"
    assert long_and_fresh, "the stored value is at least 32 characters and not the first one"
    lines = secret_tools.replace_lines(created, before)
    assert "new current version: v2" in lines[1] and "previous version: v1" in lines[2]
    printed = new_value in "\n".join(lines) or "first-secret-value" in "\n".join(lines)
    assert not printed, "the replace lines name ids and fingerprints, never a value"
    distinct = secret_tools.new_value() != secret_tools.new_value()
    assert distinct, "two generated values differ"


def test_replacement_values_are_in_the_supplied_provider_key_format() -> None:
    """Every generated value matches the supplied rule; the first version's value does not.

    The seed proves the gate finds a key in the Coldline format, so a replaced key is in
    that format too: a value that ever reaches a file is a finding under the same rule. The
    first version's value stays outside the format on purpose (T88). Every match is
    computed first and only the outcome asserted, with a constant message, so a failing
    assertion renders no generated value and no regex argument.
    """
    for _ in range(8):
        value = secret_tools.new_value()
        in_format = re.fullmatch(r"cpk_[0-9a-f]{32}", value) is not None
        assert in_format, "a generated value is cpk_ and 32 hex characters"
        matches_rule = seeds.matches_supplied_rule(value)
        assert matches_rule, "a generated value matches the supplied provider-key rule"
    unmatched = not seeds.matches_supplied_rule(FIRST_VERSION_VALUE)
    assert unmatched, "the first version's value stays outside the supplied rule's format"


def test_check_old_hands_the_previous_version_to_the_key_check_and_reports_the_refusal() -> None:
    """The previous version is refused as replaced; the lines name its id and fingerprint only."""
    store = FakeStore([("v1", "first-secret-value"), ("v2", "second-secret-value")])

    checked = asyncio.run(secret_tools.check_old(store, NAME))  # type: ignore[arg-type]
    rejected, previous, reason = checked

    assert rejected and previous.version_id == "v1"
    assert "version v1, which was replaced" in reason
    lines = secret_tools.check_old_lines(rejected, previous, reason)
    assert lines[0].startswith("secret-check-old: previous version v1 (fingerprint ")
    assert lines[0].endswith(": rejected")
    joined = "\n".join(lines)
    assert "first-secret-value" not in joined and "second-secret-value" not in joined


def test_check_old_needs_a_previous_version() -> None:
    """With one version only there is nothing to check, which is a tooling error, not a pass."""
    with pytest.raises(secret_tools.SecretToolError, match="one version only"):
        single = FakeStore([("v1", "x")])
        asyncio.run(secret_tools.check_old(single, NAME))  # type: ignore[arg-type]


def test_the_command_line_drives_the_three_commands(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """`status`, `replace` and `check-old` exit 0 on the expected outcomes and print no value."""
    store = FakeStore([("v1", "first-secret-value")])
    monkeypatch.setattr(secret_tools, "host_store", lambda root: store)

    assert secret_tools.main(["status", "--root", str(tmp_path)]) == 0
    assert secret_tools.main(["check-old", "--root", str(tmp_path)]) == 2
    assert secret_tools.main(["replace", "--root", str(tmp_path)]) == 0
    assert secret_tools.main(["check-old", "--root", str(tmp_path)]) == 0
    captured = capsys.readouterr()
    # The search is computed first: a failing assertion must not render the captured
    # output, which would carry the generated value if a command had printed it.
    printed = any(value in captured.out or value in captured.err for _, value in store.pairs)
    assert not printed, "a command printed a stored value"


def test_the_host_endpoint_follows_the_localstack_port_override(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The environment, then `.env`, then the default port."""
    monkeypatch.delenv("COLDLINE_LOCALSTACK_HOST_PORT", raising=False)
    assert secret_tools.host_endpoint(tmp_path) == "http://localhost:4566"
    (tmp_path / ".env").write_text("COLDLINE_LOCALSTACK_HOST_PORT=14566\n", encoding="utf-8")
    assert secret_tools.host_endpoint(tmp_path) == "http://localhost:14566"
    monkeypatch.setenv("COLDLINE_LOCALSTACK_HOST_PORT", "24566")
    assert secret_tools.host_endpoint(tmp_path) == "http://localhost:24566"
    store = secret_tools.host_store(tmp_path)
    assert store._client.meta.endpoint_url == "http://localhost:24566"
