"""Coldline.

===================

File:              tests/unit/adapters/test_secret_provider.py
Component:         Unit tests — LocalStack Secrets Manager adapter
Purpose:           Prove the supplied adapter reads the current version on every call, keeps no
                    cache, reports versions by id and fingerprint, creates the secret once, and
                    translates the store's errors, over a scripted client.
Interacts With:    src/adapters/secrets/localstack.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          A secret read per use, idempotent provisioning, fingerprints instead of values
Tools:             Python 3.12, pytest

The client is a scripted stand-in for boto3's Secrets Manager client: one secret, its
versions in order, the AWS stages, and the two error codes the adapter translates. No
container is touched. The values here are synthetic test strings.
"""

from __future__ import annotations

import hashlib
import uuid
from typing import Any

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError

from adapters.secrets.localstack import (
    CURRENT_STAGE,
    FIRST_VERSION_VALUE,
    PREVIOUS_STAGE,
    PROVIDER_KEY_SECRET_NAME,
    LocalStackSecretProvider,
    SecretNotFound,
    SecretUnavailable,
    SecretVersion,
    ensure_secret_when_ready,
    fingerprint,
    secret_provider,
    values_match,
)

NAME = PROVIDER_KEY_SECRET_NAME


def _client_error(code: str, operation: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}}, operation)


class ScriptedSecrets:
    """A Secrets Manager client holding one secret's versions, oldest first."""

    def __init__(self, values: list[str] | None = None) -> None:
        """Start with the given values as versions; the last is current."""
        self.versions: list[dict[str, Any]] = []
        self.calls: list[str] = []
        for value in values or []:
            self._append(value)

    def _append(self, value: str) -> str:
        for version in self.versions:
            version["stages"] = [
                PREVIOUS_STAGE if CURRENT_STAGE in version["stages"] else stage
                for stage in version["stages"]
                if stage != PREVIOUS_STAGE
            ]
        version_id = uuid.uuid4().hex
        self.versions.append({"id": version_id, "value": value, "stages": [CURRENT_STAGE]})
        return version_id

    def create_secret(self, *, Name: str, SecretString: str) -> dict[str, Any]:
        """Stand in for `create_secret`."""
        self.calls.append("create")
        if self.versions:
            raise _client_error("ResourceExistsException", "CreateSecret")
        return {"Name": Name, "VersionId": self._append(SecretString)}

    def get_secret_value(self, *, SecretId: str, VersionId: str | None = None) -> dict[str, Any]:
        """Stand in for `get_secret_value`."""
        self.calls.append("get")
        if SecretId != NAME or not self.versions:
            raise _client_error("ResourceNotFoundException", "GetSecretValue")
        if VersionId is None:
            version = next(v for v in self.versions if CURRENT_STAGE in v["stages"])
        else:
            found = [v for v in self.versions if v["id"] == VersionId]
            if not found:
                raise _client_error("ResourceNotFoundException", "GetSecretValue")
            version = found[0]
        return {
            "SecretString": version["value"],
            "VersionId": version["id"],
            "VersionStages": list(version["stages"]),
        }

    def put_secret_value(self, *, SecretId: str, SecretString: str) -> dict[str, Any]:
        """Stand in for `put_secret_value`."""
        self.calls.append("put")
        if SecretId != NAME or not self.versions:
            raise _client_error("ResourceNotFoundException", "PutSecretValue")
        return {"VersionId": self._append(SecretString), "VersionStages": [CURRENT_STAGE]}

    page_size: int | None = None

    def list_secret_version_ids(
        self, *, SecretId: str, IncludeDeprecated: bool, NextToken: str | None = None
    ) -> dict[str, Any]:
        """Stand in for `list_secret_version_ids`, paginated when `page_size` is set."""
        self.calls.append("list" if NextToken is None else f"list:{NextToken}")
        if SecretId != NAME or not self.versions:
            raise _client_error("ResourceNotFoundException", "ListSecretVersionIds")
        entries = [
            {"VersionId": v["id"], "VersionStages": list(v["stages"]), "CreatedDate": f"{i:04d}"}
            for i, v in enumerate(self.versions)
        ]
        if self.page_size is None:
            return {"Versions": entries}
        start = int(NextToken or 0)
        page = entries[start : start + self.page_size]
        response: dict[str, Any] = {"Versions": page}
        if start + self.page_size < len(entries):
            response["NextToken"] = str(start + self.page_size)
        return response


class UnreachableSecrets:
    """A client whose every call fails to connect."""

    def __getattr__(self, name: str) -> Any:
        """Stand in for `__getattr__`."""

        def fail(**kwargs: Any) -> Any:
            raise EndpointConnectionError(endpoint_url="http://localstack:4566")

        return fail


def test_fingerprint_is_a_short_stable_digest_that_is_not_the_value() -> None:
    """Twelve hex characters of the SHA-256; equal values share it; the value is not in it."""
    value = "unit-test-value-one"
    assert fingerprint(value) == hashlib.sha256(value.encode()).hexdigest()[:12]
    assert fingerprint(value) == fingerprint("unit-test-value-one")
    assert fingerprint(value) != fingerprint("unit-test-value-two")
    assert value not in fingerprint(value)
    assert values_match(value, "unit-test-value-one") and not values_match(value, "other")


async def test_read_returns_the_current_version_on_every_call_with_no_cache() -> None:
    """Each read goes to the store; after a new version the next read returns it."""
    client = ScriptedSecrets(["first-value"])
    store = LocalStackSecretProvider(client)

    assert await store.read(NAME) == "first-value"
    assert await store.read(NAME) == "first-value"
    assert client.calls.count("get") == 2

    created = await store.put_version(NAME, "second-value")
    assert created.current and created.fingerprint == fingerprint("second-value")
    assert await store.read(NAME) == "second-value"
    assert client.calls.count("get") == 3


async def test_versions_and_status_report_ids_and_fingerprints_only() -> None:
    """The version bookkeeping carries no value; the current and previous stages are told apart."""
    client = ScriptedSecrets(["first-value", "second-value"])
    store = LocalStackSecretProvider(client)

    versions = await store.versions(NAME)
    assert [v.stages for v in versions] == [(PREVIOUS_STAGE,), (CURRENT_STAGE,)]
    assert all(isinstance(v, SecretVersion) for v in versions)
    assert "first-value" not in repr(versions) and "second-value" not in repr(versions)

    status = await store.status(NAME)
    assert status.name == NAME
    assert status.current.version_id == versions[1].version_id
    assert status.previous is not None and status.previous.version_id == versions[0].version_id
    assert status.version_count == 2
    assert await store.value_of(NAME, versions[0].version_id) == "first-value"


async def test_versions_follow_the_next_token_until_every_page_is_read() -> None:
    """A paginated listing is read to the end: the current and previous versions on a later page."""
    client = ScriptedSecrets([f"value-{index}" for index in range(5)])
    client.page_size = 2
    store = LocalStackSecretProvider(client)

    versions = await store.versions(NAME)

    assert len(versions) == 5
    listings = [call for call in client.calls if call.startswith("list")]
    assert listings == ["list", "list:2", "list:4"]
    assert versions[-1].current and PREVIOUS_STAGE in versions[-2].stages
    status = await store.status(NAME)
    assert status.version_count == 5
    assert status.current.version_id == versions[-1].version_id
    assert status.previous is not None and status.previous.version_id == versions[-2].version_id


async def test_a_single_version_has_no_previous_one() -> None:
    """A secret that was never replaced reports no previous version."""
    store = LocalStackSecretProvider(ScriptedSecrets(["only"]))

    status = await store.status(NAME)

    assert status.previous is None and status.version_count == 1


async def test_ensure_secret_creates_once_and_leaves_an_existing_secret_alone() -> None:
    """The first call creates the first version; later calls return the current one unchanged."""
    client = ScriptedSecrets()
    store = LocalStackSecretProvider(client)

    created = await store.ensure_secret(NAME, FIRST_VERSION_VALUE)
    # Compared first, asserted after: a rewritten comparison would render the value.
    expected = fingerprint(FIRST_VERSION_VALUE)
    first_version_stored = created.current and created.fingerprint == expected
    assert first_version_stored, "the first call stores the supplied first version as current"

    await store.put_version(NAME, "replaced-value")
    again = await store.ensure_secret(NAME, FIRST_VERSION_VALUE)
    assert again.fingerprint == fingerprint("replaced-value"), "an existing secret is kept"
    assert await store.read(NAME) == "replaced-value"


async def test_store_errors_are_translated_and_name_no_value() -> None:
    """A missing secret or version is SecretNotFound; an unreachable store is SecretUnavailable."""
    store = LocalStackSecretProvider(ScriptedSecrets(["value"]))
    with pytest.raises(SecretNotFound, match="does not exist"):
        await store.read("coldline/other")
    with pytest.raises(SecretNotFound):
        await store.value_of(NAME, "no-such-version")
    with pytest.raises(SecretNotFound):
        await store.put_version("coldline/other", "x")

    unreachable = LocalStackSecretProvider(UnreachableSecrets())
    with pytest.raises(SecretUnavailable, match="unreachable") as excinfo:
        await unreachable.read(NAME)
    assert "value" not in str(excinfo.value)


async def test_ensure_secret_when_ready_retries_then_reports_the_endpoint() -> None:
    """The provisioning retry bounds the wait and names the endpoint, never a value."""
    unreachable = LocalStackSecretProvider(UnreachableSecrets())
    with pytest.raises(SecretUnavailable, match="did not answer after 2 attempts") as excinfo:
        await ensure_secret_when_ready(
            unreachable,
            name=NAME,
            first_value=FIRST_VERSION_VALUE,
            endpoint="http://localstack:4566",
            attempts=2,
            delay_seconds=0,
        )
    # Compared first, asserted after: a rewritten comparison would render the value.
    rendered = FIRST_VERSION_VALUE in str(excinfo.value)
    assert not rendered, "the provisioning error names the endpoint, never the value"

    ready = LocalStackSecretProvider(ScriptedSecrets())
    version = await ensure_secret_when_ready(
        ready, name=NAME, first_value=FIRST_VERSION_VALUE, endpoint="x", attempts=1
    )
    assert version.current


def test_secret_provider_builds_the_adapter_from_the_localstack_settings() -> None:
    """The composition helper takes the four LocalStack settings the worker already carries."""

    class Settings:
        s3_endpoint = "http://localhost:4566"
        s3_region = "us-east-1"
        s3_access_key_id = "localstack-development-key"
        s3_secret_access_key = "localstack-development-secret"

    store = secret_provider(Settings())

    assert isinstance(store, LocalStackSecretProvider)
    assert store._client.meta.endpoint_url == "http://localhost:4566"
    assert store._client.meta.service_model.service_name == "secretsmanager"
