"""Coldline.

===================

File:              tests/security/infra_diff.py
Component:         Infrastructure tooling — `poe infra-diff`
Purpose:           Compare the stack's bucket, queues and secret, as the startup code created
                    them, with the resources of the same names after a prefix, on the settings
                    the startup code sets, and print every difference and their count.
Interacts With:    LocalStack (host port), compose.yaml, src/api/config.py, src/api/initialize.py,
                    src/adapters/object_store/s3.py, src/adapters/queue/sqs.py,
                    src/adapters/secrets/, tests/security/iac_run.py, pyproject.toml
Sprint/Task:       Sprint 4 — Project 4 / Task 4.10
Concepts:          Two descriptions of one setup, drift, comparing only what one side sets
Tools:             Python 3.12, boto3, LocalStack

**The stack's resources** are the ones the startup code creates, named as it names them: the
bucket ``COLDLINE_S3_BUCKET`` from ``compose.yaml``; the queue and the dead-letter queue from
the defaults of ``ApiSettings`` in ``src/api/config.py`` (``compose.yaml`` may override them, and
is read for that); and the provider secret ``PROVIDER_KEY_SECRET_NAME``, the name
``docs/fidelity/SecretProvider.md`` states. Their settings are read from LocalStack, as the
running stack holds them.

**Pairing.** A stack name is ``coldline``, one separator (``-`` or ``/``) and the rest; yours is
the prefix, one separator (``-`` or ``/``, either one, whatever the stack's name uses)
and the same rest, of the same kind (bucket, queue or secret). The stack's secret
``coldline/worker/model-provider-key`` therefore pairs with
``<prefix>-worker/model-provider-key`` and with ``<prefix>/worker/model-provider-key``
alike. A stack resource with no pair is one difference. A resource of yours with no stack
pair is listed and not counted.

**What is compared** is only what the startup code sets. ``ensure_queue`` sets two things on
the queue: the visibility timeout, and the redrive policy (its maximum receive count, and its
dead-letter queue, compared by that queue's name after its owner's prefix, so the stack's
queue and yours each point at their own dead-letter queue). ``ensure_bucket`` creates the
bucket, ``ensure_queue`` creates the dead-letter queue, and the secret adapter creates the
secret with its first value; nothing else is set on those three, so being there is the
whole comparison. A setting the startup code does not set is never compared, so a stricter
setting of yours is not a difference. A secret's value is never read, and nothing about a
secret's deletion (``recovery_window_in_days``) is compared.

Exit 0 when the comparison found no difference, 1 when it found one or more, 2 when it could
not run (LocalStack unreachable, or a stack resource missing).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

import yaml
from botocore.exceptions import BotoCoreError, ClientError

from adapters.object_store import create_s3_client
from adapters.queue import create_sqs_client
from adapters.secrets import PROVIDER_KEY_SECRET_NAME, create_secrets_client
from api.config import ApiSettings
from tests.security import secret_tools, tofu

TASK_ROOT = Path(__file__).resolve().parents[2]
SEPARATORS = ("-", "/")
BUCKET = "bucket"
QUEUE = "queue"
SECRET = "secret"
# The settings compared, by the label they are printed with.
VISIBILITY = "visibility timeout"
MAX_RECEIVES = "redrive max receive count"
DEAD_LETTER = "redrive dead-letter queue"
QUEUE_SETTINGS = (VISIBILITY, MAX_RECEIVES, DEAD_LETTER)
NOT_SET = "(not set)"
PAIR = "pair"


class DiffError(RuntimeError):
    """Report that the comparison could not run, as opposed to a difference it found."""


def rest_of(name: str, prefix: str) -> str | None:
    """Return what follows ``prefix`` and one separator in ``name``, or None when it does not."""
    if len(name) <= len(prefix) + 1 or not name.startswith(prefix):
        return None
    if name[len(prefix)] not in SEPARATORS:
        return None
    return name[len(prefix) + 1 :]


@dataclass(frozen=True)
class Resource:
    """One resource as LocalStack holds it: its kind, its name and its compared settings."""

    kind: str
    name: str
    settings: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Difference:
    """One difference: the stack resource, the setting (or its missing pair), and both values."""

    resource: str
    setting: str
    stack: str
    yours: str

    def line(self) -> str:
        """Render the difference for the terminal."""
        if self.setting == PAIR:
            return f"    differs: no pair: {self.yours}"
        return f"    differs: {self.setting}: stack {self.stack}, yours {self.yours}"


@dataclass(frozen=True)
class Comparison:
    """The whole comparison: the pairs, the differences and the resources of yours left over."""

    prefix: str
    pairs: tuple[tuple[Resource, Resource | None], ...]
    differences: tuple[Difference, ...]
    unpaired_yours: tuple[str, ...]

    @property
    def count(self) -> int:
        """Return the number of differences."""
        return len(self.differences)

    def lines(self) -> list[str]:
        """Render the comparison for the terminal: each pair, each difference, the count."""
        lines = [
            f"infra-diff: the stack's resources against yours (prefix {self.prefix}), on the "
            "settings the startup code sets"
        ]
        for stack, yours in self.pairs:
            partner = yours.name if yours is not None else "nothing"
            lines.append(f"  {stack.kind:<7} {stack.name}  paired with {partner}")
            for difference in self.differences:
                if difference.resource == stack.name:
                    lines.append(difference.line())
        for name in self.unpaired_yours:
            lines.append(f"  yours, with no stack resource of that kind and name: {name}")
        lines.append(f"infra-diff: {self.count} difference(s)")
        return lines


def compare(stack: Sequence[Resource], yours: Sequence[Resource], prefix: str) -> Comparison:
    """Pair the stack's resources with yours and compare each pair on the stack's settings."""
    by_key: dict[tuple[str, str], Resource] = {}
    for resource in yours:
        rest = rest_of(resource.name, prefix)
        if rest is not None:
            by_key.setdefault((resource.kind, rest), resource)
    pairs: list[tuple[Resource, Resource | None]] = []
    differences: list[Difference] = []
    for resource in stack:
        rest = rest_of(resource.name, tofu.STACK_PREFIX) or resource.name
        mine = by_key.pop((resource.kind, rest), None)
        pairs.append((resource, mine))
        if mine is None:
            missing = f"no {resource.kind} named {prefix}-{rest} or {prefix}/{rest}"
            differences.append(Difference(resource.name, PAIR, "present", missing))
            continue
        for setting, value in resource.settings.items():
            theirs = mine.settings.get(setting, NOT_SET)
            if theirs != value:
                differences.append(Difference(resource.name, setting, value, theirs))
    leftover = tuple(sorted(resource.name for resource in by_key.values()))
    return Comparison(prefix, tuple(pairs), tuple(differences), leftover)


def queue_settings(attributes: Mapping[str, Any], owner_prefix: str) -> dict[str, str]:
    """Return a queue's compared settings from its SQS attributes.

    The dead-letter queue is named by what follows its owner's prefix, so the stack's queue
    and yours compare equal when each points at its own dead-letter queue. A target that does
    not follow the owner's prefix keeps its whole name, and differs.
    """
    settings = {setting: NOT_SET for setting in QUEUE_SETTINGS}
    visibility = attributes.get("VisibilityTimeout")
    if visibility is not None:
        settings[VISIBILITY] = str(visibility)
    policy = attributes.get("RedrivePolicy")
    if isinstance(policy, str) and policy.strip():
        try:
            document = json.loads(policy)
        except ValueError:
            document = None
        if isinstance(document, dict):
            receives = document.get("maxReceiveCount")
            if receives is not None:
                settings[MAX_RECEIVES] = str(receives).strip()
            target = document.get("deadLetterTargetArn")
            if isinstance(target, str) and target:
                name = target.rsplit(":", maxsplit=1)[-1]
                settings[DEAD_LETTER] = rest_of(name, owner_prefix) or name
    return settings


class Inventory(Protocol):
    """What the comparison reads from LocalStack."""

    def bucket_names(self) -> list[str]:
        """Return every bucket's name."""
        ...

    def queue_names(self, prefix: str) -> list[str]:
        """Return the names of the queues whose names start with ``prefix``."""
        ...

    def queue_attributes(self, name: str) -> dict[str, Any] | None:
        """Return one queue's attributes, or None when it does not exist."""
        ...

    def secret_names(self) -> list[str]:
        """Return the names of the secrets that exist and are not scheduled for deletion."""
        ...


class LocalStackInventory:
    """Read buckets, queues and secrets from LocalStack on the host port the stack publishes."""

    def __init__(self, endpoint: str) -> None:
        """Bind the three clients to the LocalStack endpoint and its development credentials."""
        credentials = {
            "endpoint_url": endpoint,
            "region_name": secret_tools.LOCALSTACK_REGION,
            "access_key_id": secret_tools.LOCALSTACK_ACCESS_KEY_ID,
            "secret_access_key": secret_tools.LOCALSTACK_SECRET_ACCESS_KEY,
        }
        self._endpoint = endpoint
        self._s3 = create_s3_client(**credentials)
        self._sqs = create_sqs_client(**credentials)
        self._secrets = create_secrets_client(**credentials)

    def _unreachable(self, exc: Exception) -> DiffError:
        return DiffError(
            f"LocalStack at {self._endpoint} did not answer ({exc}); is the stack running "
            "(`poe start`), and is COLDLINE_LOCALSTACK_HOST_PORT the port it published?"
        )

    def bucket_names(self) -> list[str]:
        """Return every bucket's name."""
        try:
            response = self._s3.list_buckets()
        except (BotoCoreError, ClientError) as exc:
            raise self._unreachable(exc) from exc
        return sorted(str(bucket.get("Name", "")) for bucket in response.get("Buckets", []))

    def queue_names(self, prefix: str) -> list[str]:
        """Return the names of the queues whose names start with ``prefix``."""
        try:
            response = self._sqs.list_queues(QueueNamePrefix=prefix)
        except (BotoCoreError, ClientError) as exc:
            raise self._unreachable(exc) from exc
        urls = response.get("QueueUrls", [])
        return sorted(str(url).rstrip("/").rsplit("/", maxsplit=1)[-1] for url in urls)

    def queue_attributes(self, name: str) -> dict[str, Any] | None:
        """Return one queue's attributes, or None when it does not exist."""
        try:
            url = self._sqs.get_queue_url(QueueName=name)["QueueUrl"]
        except ClientError:
            return None
        except BotoCoreError as exc:
            raise self._unreachable(exc) from exc
        try:
            response = self._sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["All"])
        except (BotoCoreError, ClientError) as exc:
            raise self._unreachable(exc) from exc
        attributes = response.get("Attributes", {})
        return dict(attributes) if isinstance(attributes, dict) else {}

    def secret_names(self) -> list[str]:
        """Return the names of the secrets that exist and are not scheduled for deletion."""
        names: list[str] = []
        token: str | None = None
        while True:
            arguments: dict[str, Any] = {}
            if token is not None:
                arguments["NextToken"] = token
            try:
                response = self._secrets.list_secrets(**arguments)
            except (BotoCoreError, ClientError) as exc:
                raise self._unreachable(exc) from exc
            for entry in response.get("SecretList", []):
                if isinstance(entry, dict) and not entry.get("DeletedDate"):
                    names.append(str(entry.get("Name", "")))
            next_token = response.get("NextToken")
            if not next_token:
                return sorted(names)
            token = str(next_token)


@dataclass(frozen=True)
class StackNames:
    """The names the startup code gives the stack's bucket, queues and secret."""

    bucket: str
    queue: str
    dead_letter_queue: str
    secret: str


def stack_names(root: Path = TASK_ROOT) -> StackNames:
    """Return the stack's resource names from compose.yaml, ApiSettings and the secret adapter."""
    try:
        compose = yaml.safe_load((root / "compose.yaml").read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise DiffError(f"compose.yaml could not be read: {exc}") from exc
    environment = compose.get("x-coldline-environment") if isinstance(compose, dict) else None
    values = environment if isinstance(environment, dict) else {}
    fields = ApiSettings.model_fields

    def named(variable: str, field_name: str) -> str:
        value = values.get(variable)
        return str(value) if value else str(fields[field_name].default)

    return StackNames(
        bucket=named("COLDLINE_S3_BUCKET", "s3_bucket"),
        queue=named("COLDLINE_QUEUE_NAME", "queue_name"),
        dead_letter_queue=named("COLDLINE_DEAD_LETTER_QUEUE_NAME", "dead_letter_queue_name"),
        secret=PROVIDER_KEY_SECRET_NAME,
    )


def stack_resources(inventory: Inventory, names: StackNames) -> list[Resource]:
    """Return the stack's resources as LocalStack holds them, or fail naming a missing one."""
    missing: list[str] = []
    if names.bucket not in inventory.bucket_names():
        missing.append(names.bucket)
    queue = inventory.queue_attributes(names.queue)
    if queue is None:
        missing.append(names.queue)
    if inventory.queue_attributes(names.dead_letter_queue) is None:
        missing.append(names.dead_letter_queue)
    if names.secret not in inventory.secret_names():
        missing.append(names.secret)
    if missing or queue is None:
        raise DiffError(
            f"the stack's {', '.join(missing)} does not exist in LocalStack; start the stack "
            "(`poe start`) so the startup code creates it"
        )
    return [
        Resource(BUCKET, names.bucket),
        Resource(QUEUE, names.queue, queue_settings(queue, tofu.STACK_PREFIX)),
        Resource(QUEUE, names.dead_letter_queue),
        Resource(SECRET, names.secret),
    ]


def your_resources(inventory: Inventory, prefix: str) -> list[Resource]:
    """Return every bucket, queue and secret named from ``prefix`` and one separator."""
    resources: list[Resource] = []
    for name in inventory.bucket_names():
        if rest_of(name, prefix) is not None:
            resources.append(Resource(BUCKET, name))
    for name in inventory.queue_names(prefix):
        if rest_of(name, prefix) is None:
            continue
        attributes = inventory.queue_attributes(name)
        if attributes is not None:
            resources.append(Resource(QUEUE, name, queue_settings(attributes, prefix)))
    for name in inventory.secret_names():
        if rest_of(name, prefix) is not None:
            resources.append(Resource(SECRET, name))
    return resources


def check_prefix(prefix: str) -> None:
    """Refuse the stack's own prefix: comparing the stack with itself proves nothing."""
    if prefix == tofu.STACK_PREFIX or not prefix:
        raise DiffError("the prefix must name your resources, not the stack's own `coldline`")


def run(
    root: Path = TASK_ROOT, prefix: str = tofu.SANDBOX_PREFIX, inventory: Inventory | None = None
) -> Comparison:
    """Read both sets from LocalStack and compare them."""
    check_prefix(prefix)
    store = inventory
    if store is None:
        store = LocalStackInventory(secret_tools.host_endpoint(root))
    stack = stack_resources(store, stack_names(root))
    return compare(stack, your_resources(store, prefix), prefix)


def main(argv: list[str] | None = None) -> int:
    """Compare and print; exit 0 with no difference, 1 with differences, 2 when it cannot run."""
    parser = argparse.ArgumentParser(
        description="Compare the stack's resources with yours on the startup code's settings."
    )
    parser.add_argument("--root", type=Path, default=TASK_ROOT)
    parser.add_argument(
        "--prefix",
        default=tofu.SANDBOX_PREFIX,
        help="the prefix your resources are named from (default: coldline-sandbox)",
    )
    arguments = parser.parse_args(argv)
    try:
        comparison = run(arguments.root.resolve(), arguments.prefix)
    except (DiffError, ValueError) as exc:
        print(f"infra-diff: {exc}", file=sys.stderr)
        return 2
    for line in comparison.lines():
        print(line)
    return 0 if comparison.count == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
