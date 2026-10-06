"""Coldline.

===================

File:              src/adapters/secrets/localstack.py
Component:         Adapter — LocalStack Secrets Manager
Purpose:           Implement the SecretProvider port against LocalStack Secrets Manager: read the
                    current version of a secret on every call, and give the composition roots
                    and the Task's tools the version bookkeeping they need.
Interacts With:    ports.SecretProvider, src/worker/config.py, src/worker/bootstrap.py,
                    src/api/initialize.py, src/adapters/model/provider_keys.py,
                    tests/security/secret_tools.py, docs/fidelity/SecretProvider.md
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          Secret read on every use, no cache and no TTL, versions as evidence,
                    fingerprints instead of values
Tools:             Python 3.12, boto3, LocalStack

Supplied and settled: call it, do not edit it. ``LocalStackSecretProvider.read(name)``
returns the secret's **current** version on every call. It keeps no cache and no TTL on
purpose: the model emulator accepts only the current version of the provider key, so a
value read once and kept would be refused the moment the key is replaced
(``docs/fidelity/SecretProvider.md``). The other methods are the bookkeeping the Task's
tools and checks need, and none of them prints a value: a version is reported by its id
and by a short fingerprint of its value (``fingerprint``: the first twelve hex characters
of the value's SHA-256), which lets two people agree they are looking at the same version
without either seeing it.

Call form, from the worker's settings module::

    from adapters.secrets import PROVIDER_KEY_SECRET_NAME, secret_provider

    key = await secret_provider(settings).read(PROVIDER_KEY_SECRET_NAME)

``secret_provider(settings)`` builds the adapter from the LocalStack endpoint and the
development credentials the settings already carry for the queue; the worker's settings
satisfy ``LocalStackEndpoint``. The initializer creates the provider key's secret at
startup (``ensure_secret_when_ready``) with its first version equal to the opening
checkpoint's committed configuration literal (``FIRST_VERSION_VALUE``), which is the value
the Task's Step 2 replaces.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
from dataclasses import dataclass
from typing import Any, Protocol

import boto3
from botocore.client import Config
from botocore.exceptions import BotoCoreError, ClientError

# The one secret this Project's worker reads: the model provider's key.
PROVIDER_KEY_SECRET_NAME = "coldline/worker/model-provider-key"
# The local store's first version of that secret: the value the opening checkpoint carried
# as a configuration literal. The initializer writes it once, when the secret does not
# exist yet; the Task's Step 2 replaces it. It matches no scanner rule.
FIRST_VERSION_VALUE = "coldline-dev-provider-key-v1"
FINGERPRINT_CHARACTERS = 12
CURRENT_STAGE = "AWSCURRENT"
PREVIOUS_STAGE = "AWSPREVIOUS"
_NOT_FOUND_CODES = frozenset({"ResourceNotFoundException"})
_EXISTS_CODES = frozenset({"ResourceExistsException"})


class SecretUnavailable(RuntimeError):
    """Report that the secret store did not answer, or refused the operation."""


class SecretNotFound(SecretUnavailable):
    """Report that the named secret, or the named version of it, does not exist."""


def fingerprint(value: str) -> str:
    """Return the short fingerprint of a secret value: the start of its SHA-256 hex digest.

    A fingerprint identifies a version without revealing it. It holds for a long random
    value like the provider key; a fingerprint of a short or guessable value could be
    matched by hashing guesses, which is why the Task's tools print it for this key only.
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:FINGERPRINT_CHARACTERS]


def values_match(presented: str, stored: str) -> bool:
    """Compare two secret values in constant time."""
    return hmac.compare_digest(presented.encode("utf-8"), stored.encode("utf-8"))


@dataclass(frozen=True)
class SecretVersion:
    """One version of a secret: its id, its fingerprint, and the stages it carries.

    The value is not here. Code that needs it calls ``LocalStackSecretProvider.value_of``
    and keeps it out of every log, record and message.
    """

    version_id: str
    fingerprint: str
    stages: tuple[str, ...] = ()

    @property
    def current(self) -> bool:
        """Return whether this version is the one a read returns."""
        return CURRENT_STAGE in self.stages


@dataclass(frozen=True)
class SecretStatus:
    """What `poe secret-status` prints: the current and previous versions, and how many exist."""

    name: str
    current: SecretVersion
    previous: SecretVersion | None
    version_count: int


class LocalStackEndpoint(Protocol):
    """The settings a composition root supplies to reach LocalStack: endpoint and credentials."""

    @property
    def s3_endpoint(self) -> str:
        """Return LocalStack's edge endpoint, which serves every emulated service."""
        ...

    @property
    def s3_region(self) -> str:
        """Return the region the development credentials are scoped to."""
        ...

    @property
    def s3_access_key_id(self) -> str:
        """Return the LocalStack development access key id."""
        ...

    @property
    def s3_secret_access_key(self) -> str:
        """Return the LocalStack development secret access key."""
        ...


def create_secrets_client(
    *,
    endpoint_url: str,
    region_name: str,
    access_key_id: str,
    secret_access_key: str,
) -> Any:
    """Create one Secrets Manager client for a composition root.

    Only a composition root calls this. Application code receives the ``SecretProvider``
    port and never sees a client, an endpoint, or a credential.
    """
    return boto3.client(
        "secretsmanager",
        endpoint_url=endpoint_url,
        region_name=region_name,
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
        config=Config(retries={"max_attempts": 3, "mode": "standard"}),
    )


def secret_provider(settings: LocalStackEndpoint) -> LocalStackSecretProvider:
    """Build the supplied adapter from the LocalStack endpoint and credentials settings carry."""
    return LocalStackSecretProvider(
        create_secrets_client(
            endpoint_url=settings.s3_endpoint,
            region_name=settings.s3_region,
            access_key_id=settings.s3_access_key_id,
            secret_access_key=settings.s3_secret_access_key,
        )
    )


def _code_of(exc: ClientError) -> str:
    """Return the service error code of one client error."""
    error = exc.response.get("Error", {})
    code = error.get("Code", "")
    return str(code)


class LocalStackSecretProvider:
    """Read secrets from LocalStack Secrets Manager, current version first, every time.

    The client is synchronous, so every call runs on a worker thread. Provider errors are
    translated at this boundary into ``SecretUnavailable`` (and ``SecretNotFound`` for a
    missing secret or version); the value of a secret is returned by ``read`` and
    ``value_of`` alone, and appears in no exception message.

    Fidelity: against LocalStack this adapter exercises the Secrets Manager calls it
    makes, and nothing more. It shows that the worker reads the current version on each
    use and that a replaced value takes effect without a restart; it shows nothing of how
    AWS IAM would decide who may read the secret, or how KMS would store it. See
    ``docs/fidelity/SecretProvider.md``.
    """

    def __init__(self, client: Any) -> None:
        """Bind the adapter to one Secrets Manager client."""
        self._client = client

    async def read(self, name: str) -> str:
        """Return the current version's value, read from the store now (the port's one method)."""
        version, value = await self.current_value(name)
        return value

    async def current_value(self, name: str) -> tuple[SecretVersion, str]:
        """Return the current version and its value, from one store call."""
        return await asyncio.to_thread(self._get_value, name, None)

    async def current_version(self, name: str) -> SecretVersion:
        """Return the current version, by id and fingerprint."""
        version, _ = await self.current_value(name)
        return version

    async def value_of(self, name: str, version_id: str) -> str:
        """Return one version's value by its id (the authenticator's and the tools' read)."""
        _, value = await asyncio.to_thread(self._get_value, name, version_id)
        return value

    async def versions(self, name: str) -> list[SecretVersion]:
        """Return every version the store still holds, oldest first, with its stages."""
        return await asyncio.to_thread(self._versions, name)

    async def status(self, name: str) -> SecretStatus:
        """Return the current and previous versions and the version count."""
        versions = await self.versions(name)
        current = next((item for item in versions if item.current), None)
        if current is None:
            raise SecretNotFound(f"secret {name} has no current version")
        previous = next((item for item in versions if PREVIOUS_STAGE in item.stages), None)
        return SecretStatus(name, current, previous, len(versions))

    async def put_version(self, name: str, value: str) -> SecretVersion:
        """Store ``value`` as the secret's new current version and return that version."""
        return await asyncio.to_thread(self._put_version, name, value)

    async def ensure_secret(self, name: str, first_value: str) -> SecretVersion:
        """Create the secret with ``first_value`` when it is absent; return the current version.

        Idempotent: a secret that exists is left as it is, whatever its current version
        holds, so a restart or a Codespaces resume never undoes a replacement.
        """
        return await asyncio.to_thread(self._ensure_secret, name, first_value)

    def _get_value(self, name: str, version_id: str | None) -> tuple[SecretVersion, str]:
        arguments: dict[str, Any] = {"SecretId": name}
        if version_id is not None:
            arguments["VersionId"] = version_id
        try:
            response = self._client.get_secret_value(**arguments)
        except ClientError as exc:
            if _code_of(exc) in _NOT_FOUND_CODES:
                raise SecretNotFound(
                    f"secret {name} (version {version_id or 'current'}) does not exist"
                ) from exc
            raise SecretUnavailable(f"the secret store refused the read of {name}") from exc
        except BotoCoreError as exc:
            raise SecretUnavailable(f"the secret store is unreachable for {name}") from exc
        value = response.get("SecretString")
        if not isinstance(value, str):
            raise SecretUnavailable(f"secret {name} holds no string value")
        stages = tuple(str(stage) for stage in response.get("VersionStages", ()))
        version = SecretVersion(str(response.get("VersionId", "")), fingerprint(value), stages)
        return version, value

    def _list_versions(self, name: str) -> list[dict[str, Any]]:
        """Return every version entry the store lists, following ``NextToken`` to the end.

        One ``list_secret_version_ids`` response is a page; a secret that `poe verify` has
        replaced many times has more versions than one page holds, and the status, the
        previous-version check and the no-value row must see every one of them.
        """
        entries: list[dict[str, Any]] = []
        token: str | None = None
        while True:
            arguments: dict[str, Any] = {"SecretId": name, "IncludeDeprecated": True}
            if token is not None:
                arguments["NextToken"] = token
            try:
                response = self._client.list_secret_version_ids(**arguments)
            except ClientError as exc:
                if _code_of(exc) in _NOT_FOUND_CODES:
                    raise SecretNotFound(f"secret {name} does not exist") from exc
                raise SecretUnavailable(f"the secret store refused to list {name}") from exc
            except BotoCoreError as exc:
                raise SecretUnavailable(f"the secret store is unreachable for {name}") from exc
            entries.extend(response.get("Versions", []))
            token = response.get("NextToken")
            if not token:
                return entries

    def _versions(self, name: str) -> list[SecretVersion]:
        entries = sorted(
            self._list_versions(name),
            key=lambda entry: (str(entry.get("CreatedDate", "")), str(entry.get("VersionId", ""))),
        )
        versions: list[SecretVersion] = []
        for entry in entries:
            version_id = str(entry.get("VersionId", ""))
            if not version_id:
                continue
            _, value = self._get_value(name, version_id)
            stages = tuple(str(stage) for stage in entry.get("VersionStages", ()))
            versions.append(SecretVersion(version_id, fingerprint(value), stages))
        return versions

    def _put_version(self, name: str, value: str) -> SecretVersion:
        try:
            response = self._client.put_secret_value(SecretId=name, SecretString=value)
        except ClientError as exc:
            if _code_of(exc) in _NOT_FOUND_CODES:
                raise SecretNotFound(f"secret {name} does not exist") from exc
            raise SecretUnavailable(f"the secret store refused the new version of {name}") from exc
        except BotoCoreError as exc:
            raise SecretUnavailable(f"the secret store is unreachable for {name}") from exc
        stages = tuple(str(stage) for stage in response.get("VersionStages", (CURRENT_STAGE,)))
        return SecretVersion(str(response.get("VersionId", "")), fingerprint(value), stages)

    def _ensure_secret(self, name: str, first_value: str) -> SecretVersion:
        try:
            response = self._client.create_secret(Name=name, SecretString=first_value)
        except ClientError as exc:
            if _code_of(exc) in _EXISTS_CODES:
                version, _ = self._get_value(name, None)
                return version
            raise SecretUnavailable(f"the secret store refused to create {name}") from exc
        except BotoCoreError as exc:
            raise SecretUnavailable(f"the secret store is unreachable for {name}") from exc
        return SecretVersion(
            str(response.get("VersionId", "")), fingerprint(first_value), (CURRENT_STAGE,)
        )


async def ensure_secret_when_ready(
    store: LocalStackSecretProvider,
    *,
    name: str,
    first_value: str,
    endpoint: str,
    attempts: int = 30,
    delay_seconds: float = 2.0,
) -> SecretVersion:
    """Retry the idempotent creation until the secret store answers, as the queue adapter does.

    A composition root awaits this instead of catching a cloud SDK exception type
    itself, so ``botocore`` stays an adapter-only import.
    """
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            return await store.ensure_secret(name, first_value)
        except SecretUnavailable as exc:
            last_error = exc
            if attempt + 1 < attempts:
                await asyncio.sleep(delay_seconds)
    raise SecretUnavailable(
        f"the secret store at {endpoint} did not answer after {attempts} attempts; start the "
        "stack with the localstack Compose profile enabled (`poe start`)"
    ) from last_error


__all__ = [
    "CURRENT_STAGE",
    "FIRST_VERSION_VALUE",
    "PREVIOUS_STAGE",
    "PROVIDER_KEY_SECRET_NAME",
    "LocalStackEndpoint",
    "LocalStackSecretProvider",
    "SecretNotFound",
    "SecretStatus",
    "SecretUnavailable",
    "SecretVersion",
    "create_secrets_client",
    "ensure_secret_when_ready",
    "fingerprint",
    "secret_provider",
    "values_match",
]
