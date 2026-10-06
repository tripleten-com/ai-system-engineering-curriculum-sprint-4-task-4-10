"""Coldline.

===================

File:              tests/security/secret_tools.py
Component:         Security tooling — The secret store from the host
Purpose:           `poe secret-status`, `poe secret-replace` and `poe secret-check-old` over the
                    provider key in LocalStack Secrets Manager, and the read of the worker's
                    authentication record the checks share with `poe provider-auth-check`.
Interacts With:    src/adapters/secrets/localstack.py, src/adapters/model/provider_keys.py,
                    src/worker/provider_auth.py (through `docker compose exec`),
                    tests/runtime_config.py, tests/contract/test_security_contract.py,
                    docs/fidelity/SecretProvider.md, pyproject.toml
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          Versions and fingerprints as evidence, never a value on the terminal
Tools:             Python 3.12, boto3, LocalStack, Docker Compose

The three commands reach LocalStack on the host port the stack publishes
(``COLDLINE_LOCALSTACK_HOST_PORT``, the environment, then ``.env``, then 4566) with the
LocalStack development credentials from ``compose.yaml``, through the same supplied
adapter the worker uses. None of them prints a secret value:

- ``status``: the current version's id and fingerprint, the previous version's when there
  is one, and the number of versions;
- ``replace``: generates a new value in the Coldline provider-key format (``cpk_`` and 32
  hex characters, which the supplied Gitleaks rule matches), stores it as the current
  version, and prints the new version's id and fingerprint and the id of the version that
  is now the previous one;
- ``check-old``: reads the previous version, asks the emulator's key check (the same class
  the worker's provider is composed with) to authenticate it, and reports the refusal
  (exit 0) or, which must not happen, an acceptance (exit 1); exit 2 when the store holds
  one version only.

``provider_auth_record`` reads the worker container's record as JSON through ``docker
compose exec``; ``poe provider-auth-check`` prints the same record as text inside the
container. ``value_findings`` is the one place the assessed rows look for a version's value
in a text: it returns findings that name the version and the text's label, never the value,
so a failing row renders nothing but ids (``tests/unit/security/test_value_findings.py``
runs a failing probe under pytest and reads its output and junit report for a sentinel).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import secrets
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from adapters.model.provider_keys import ProviderKeyRejected, SecretStoreKeyAuthenticator
from adapters.secrets import (
    PROVIDER_KEY_SECRET_NAME,
    LocalStackSecretProvider,
    SecretStatus,
    SecretUnavailable,
    SecretVersion,
    create_secrets_client,
)
from tests.runtime_config import host_port
from tests.security import seeds

TASK_ROOT = Path(__file__).resolve().parents[2]
# The LocalStack development values compose.yaml sets; they grant nothing outside the
# local Compose network and are not secrets.
LOCALSTACK_REGION = "us-east-1"
LOCALSTACK_ACCESS_KEY_ID = "localstack-development-key"
LOCALSTACK_SECRET_ACCESS_KEY = "localstack-development-secret"
# A replacement value is a key in the Coldline provider-key format the supplied Gitleaks
# rule matches (`cpk_` and 32 hex characters: sixteen random bytes), so a replaced key that
# ever reaches a file is a finding under the rule the seed proves. The first version's
# value is the one key outside that format, on purpose (T88).
NEW_VALUE_BYTES = 16
COMPOSE: tuple[str, ...] = (
    "docker",
    "compose",
    "--profile",
    "observability",
    "--profile",
    "localstack",
)
AUTH_RECORD_COMMAND: tuple[str, ...] = ("python", "-m", "worker.provider_auth", "--json")
COMMAND_TIMEOUT_SECONDS = 60


class SecretToolError(RuntimeError):
    """Report that the store or the worker container could not be reached."""


def host_endpoint(root: Path = TASK_ROOT) -> str:
    """Return LocalStack's host endpoint, honouring the port override."""
    return f"http://localhost:{host_port('COLDLINE_LOCALSTACK_HOST_PORT', 4566, root=root)}"


def host_store(root: Path = TASK_ROOT) -> LocalStackSecretProvider:
    """Return the supplied adapter bound to LocalStack on the host."""
    return LocalStackSecretProvider(
        create_secrets_client(
            endpoint_url=host_endpoint(root),
            region_name=LOCALSTACK_REGION,
            access_key_id=LOCALSTACK_ACCESS_KEY_ID,
            secret_access_key=LOCALSTACK_SECRET_ACCESS_KEY,
        )
    )


def new_value() -> str:
    """Return a fresh random key for `secret-replace`, in the Coldline provider-key format."""
    return seeds.KEY_PREFIX + secrets.token_hex(NEW_VALUE_BYTES)


def _version_line(label: str, version: SecretVersion | None) -> str:
    if version is None:
        return f"  {label}: none"
    return f"  {label}: {version.version_id} (fingerprint {version.fingerprint})"


def status_lines(status: SecretStatus) -> list[str]:
    """Render `secret-status`."""
    return [
        f"secret-status: {status.name}",
        _version_line("current version", status.current),
        _version_line("previous version", status.previous),
        f"  versions held: {status.version_count}",
    ]


async def replace(
    store: LocalStackSecretProvider, name: str = PROVIDER_KEY_SECRET_NAME, value: str | None = None
) -> tuple[SecretVersion, SecretVersion]:
    """Store a new current version; return it and the version that was current before."""
    before = await store.current_version(name)
    created = await store.put_version(name, new_value() if value is None else value)
    return created, before


def replace_lines(created: SecretVersion, before: SecretVersion) -> list[str]:
    """Render `secret-replace`."""
    return [
        f"secret-replace: {PROVIDER_KEY_SECRET_NAME}",
        _version_line("new current version", created),
        f"  previous version: {before.version_id} (fingerprint {before.fingerprint})",
        "  The worker's next request presents whatever its settings return now; run "
        "`poe scenario`, then `poe provider-auth-check`.",
    ]


async def check_old(
    store: LocalStackSecretProvider, name: str = PROVIDER_KEY_SECRET_NAME
) -> tuple[bool, SecretVersion, str]:
    """Authenticate the previous version with the emulator's key check.

    Returns whether it was rejected, the previous version, and the reason or the acceptance.
    """
    status = await store.status(name)
    if status.previous is None:
        raise SecretToolError(
            f"{name} holds one version only; run `poe secret-replace` first, then check the "
            "previous version"
        )
    previous = status.previous
    value = await store.value_of(name, previous.version_id)
    authenticator = SecretStoreKeyAuthenticator(store, name=name)
    try:
        await authenticator.authenticate(value)
    except ProviderKeyRejected as exc:
        return True, previous, str(exc)
    return False, previous, "accepted as the current version"


def check_old_lines(rejected: bool, previous: SecretVersion, reason: str) -> list[str]:
    """Render `secret-check-old`."""
    verdict = "rejected" if rejected else "ACCEPTED"
    return [
        f"secret-check-old: previous version {previous.version_id} (fingerprint "
        f"{previous.fingerprint}): {verdict}",
        f"  {reason}",
    ]


def value_findings(
    outputs: Mapping[str, str], versions: Sequence[tuple[SecretVersion, str]]
) -> list[str]:
    """Return one finding per (version, output) whose text holds that version's value.

    The comparison happens here, and only its outcome leaves: a finding names the version
    id, the fingerprint and the output's label. Callers assert on the returned list, so a
    failing assertion renders these strings and never a value (pytest's assertion
    rewriting shows the operands of the assertion it rewrites, which is why the rows do not
    write ``value not in text`` themselves).
    """
    findings: list[str] = []
    for version, value in versions:
        if not value:
            continue
        for label, text in outputs.items():
            if value in text:
                findings.append(
                    f"version {version.version_id} (fingerprint {version.fingerprint})'s value "
                    f"appears in {label}"
                )
    return findings


def provider_auth_record(root: Path = TASK_ROOT) -> dict[str, Any]:
    """Return the worker container's authentication record as `provider_auth --json` prints it."""
    try:
        completed = subprocess.run(
            [*COMPOSE, "exec", "-T", "worker", *AUTH_RECORD_COMMAND],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SecretToolError(
            f"the worker's authentication record could not be read: {exc}"
        ) from exc
    if completed.returncode == 2:
        raise SecretToolError(
            "the worker keeps no authentication record (COLDLINE_PROVIDER_AUTH_RECORD is not set "
            "in compose.yaml)"
        )
    if completed.returncode not in {0, 1}:
        raise SecretToolError(
            f"the worker's authentication record could not be read (exit {completed.returncode}): "
            f"{completed.stderr.strip()}"
        )
    try:
        loaded = json.loads(completed.stdout)
    except ValueError as exc:
        raise SecretToolError("the worker's authentication record is not JSON") from exc
    if not isinstance(loaded, dict):
        raise SecretToolError("the worker's authentication record is not a JSON object")
    return dict(loaded)


def main(argv: list[str] | None = None) -> int:
    """Run one of the three commands against the host store."""
    parser = argparse.ArgumentParser(description="Inspect or replace the provider key's secret.")
    parser.add_argument("command", choices=("status", "replace", "check-old"))
    parser.add_argument("--root", type=Path, default=TASK_ROOT)
    arguments = parser.parse_args(argv)
    store = host_store(arguments.root)
    try:
        if arguments.command == "status":
            for line in status_lines(asyncio.run(store.status(PROVIDER_KEY_SECRET_NAME))):
                print(line)
            return 0
        if arguments.command == "replace":
            created, before = asyncio.run(replace(store))
            for line in replace_lines(created, before):
                print(line)
            return 0
        rejected, previous, reason = asyncio.run(check_old(store))
    except SecretUnavailable as exc:
        print(
            f"{arguments.command}: {exc}; is the stack running (`poe start`), and is "
            f"COLDLINE_LOCALSTACK_HOST_PORT the port it published?",
            file=sys.stderr,
        )
        return 2
    except SecretToolError as exc:
        print(f"{arguments.command}: {exc}", file=sys.stderr)
        return 2
    for line in check_old_lines(rejected, previous, reason):
        print(line)
    return 0 if rejected else 1


if __name__ == "__main__":
    raise SystemExit(main())
