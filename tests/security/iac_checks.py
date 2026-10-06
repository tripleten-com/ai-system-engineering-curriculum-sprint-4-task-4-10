"""Coldline.

===================

File:              tests/security/iac_checks.py
Component:         Infrastructure tooling — What a plan and the files under infra/tofu/ declare
Purpose:           Read a saved OpenTofu plan for the resources it would create, their names and
                    the references their settings make, and read the files under infra/tofu/ for
                    a secret version or a secret value, a block the declarations may not hold,
                    and an inline scanner ignore.
Interacts With:    tests/security/iac_run.py, tests/contract/test_iac_contract.py,
                    tests/security/infra_diff.py, src/adapters/secrets/, tests/security/seeds.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.10
Concepts:          A plan as the reviewable record of a change, references as tracked dependencies
Tools:             Python 3.12, OpenTofu's JSON plan format

Everything here reads data and returns findings; nothing runs OpenTofu. The plan is the JSON
``tofu show -json`` prints for a saved plan: ``resource_changes`` says what would be created,
``planned_values`` what each resource would be named, and ``configuration`` what each
setting's expression refers to (a reference to another resource is listed there; a string
typed out in full is a ``constant_value`` instead).
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from adapters.secrets import FIRST_VERSION_VALUE
from tests.security import infra_diff, repository, seeds, tofu

BUCKET_TYPE = "aws_s3_bucket"
QUEUE_TYPE = "aws_sqs_queue"
SECRET_TYPE = "aws_secretsmanager_secret"
SECRET_VERSION_TYPE = "aws_secretsmanager_secret_version"
# The attribute each type is named by.
NAME_ATTRIBUTE = {BUCKET_TYPE: "bucket", QUEUE_TYPE: "name", SECRET_TYPE: "name"}
DATA_PREFIX = "data."
# A block label, quoted or not: HCL accepts both.
LABEL = r"""(?:"[^"\n]*"|[A-Za-z_][\w-]*)"""
# A secret version declared as a resource, or read as a data source: either puts the value in
# the state.
SECRET_VERSION_BLOCK = re.compile(
    r"""(?:resource|data)\s+"?aws_secretsmanager_secret_version"?\s+""" + LABEL + r"""\s*\{"""
)
INDEX = re.compile(r"\[[^\]]*\]$")
# A scanner ignore written beside a resource instead of in infra/tofu/.trivyignore.
INLINE_IGNORE = re.compile(r"(?i)\b(?:trivy|tfsec):ignore\b")
# Blocks your declarations may not hold: settings, a state backend, another provider, a module,
# a command OpenTofu would run, or a block that takes over or lets go of an existing resource.
# providers.tf and variables.tf supply what the run needs.
FORBIDDEN_NAMES = "terraform|backend|cloud|provider|module|provisioner|connection|import|removed"
FORBIDDEN_BLOCK = re.compile(
    r"""(?m)^[ \t]*(""" + FORBIDDEN_NAMES + r""")\b[ \t]*(?:""" + LABEL + r"""[ \t]*)*\{"""
)
FORBIDDEN_JSON_KEY = re.compile(r""""(""" + FORBIDDEN_NAMES + r""")"\s*:\s*[\[{]""")
# The provider configurations providers.tf supplies, as the plan's configuration names them.
SUPPLIED_PROVIDER_CONFIGS = frozenset({"aws"})


@dataclass(frozen=True)
class Expected:
    """One resource the declarations must hold: its role, type and the stack name it copies."""

    role: str
    resource_type: str
    stack_name: str

    @property
    def rest(self) -> str:
        """Return the stack name after ``coldline`` and its separator."""
        return infra_diff.rest_of(self.stack_name, tofu.STACK_PREFIX) or self.stack_name


def expected_resources(names: infra_diff.StackNames) -> tuple[Expected, ...]:
    """Return the resources a sandbox copy of the stack declares, from the stack's own names."""
    return (
        Expected("bucket", BUCKET_TYPE, names.bucket),
        Expected("queue", QUEUE_TYPE, names.queue),
        Expected("dead-letter queue", QUEUE_TYPE, names.dead_letter_queue),
        Expected("secret", SECRET_TYPE, names.secret),
    )


@dataclass(frozen=True)
class Planned:
    """One managed resource a plan would create: its address, type and name."""

    address: str
    resource_type: str
    name: str | None


def config_address(address: str) -> str:
    """Return a resource address without its ``count`` or ``for_each`` index."""
    return INDEX.sub("", address)


def created(plan: Mapping[str, Any]) -> list[Planned]:
    """Return the managed resources the plan would create, with the names it plans for them."""
    values: dict[str, Mapping[str, Any]] = {}
    root = plan.get("planned_values")
    module = root.get("root_module") if isinstance(root, Mapping) else None
    for resource in _module_resources(module):
        address = resource.get("address")
        planned = resource.get("values")
        if isinstance(address, str) and isinstance(planned, Mapping):
            values[address] = planned
    found: list[Planned] = []
    for change in plan.get("resource_changes") or []:
        if not isinstance(change, Mapping) or change.get("mode") != "managed":
            continue
        details = change.get("change")
        actions = details.get("actions") if isinstance(details, Mapping) else None
        if not isinstance(actions, list) or "create" not in actions:
            continue
        address = str(change.get("address", ""))
        resource_type = str(change.get("type", ""))
        attribute = NAME_ATTRIBUTE.get(resource_type, "name")
        name = values.get(address, {}).get(attribute)
        found.append(Planned(address, resource_type, name if isinstance(name, str) else None))
    return found


def _module_resources(module: Any) -> Iterable[Mapping[str, Any]]:
    """Yield the resources of a planned or configured module and of every module it calls."""
    if not isinstance(module, Mapping):
        return
    for resource in module.get("resources") or []:
        if isinstance(resource, Mapping):
            yield resource
    for child in module.get("child_modules") or []:
        yield from _module_resources(child)


def configured(plan: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    """Return each configured resource's expressions, by its configuration address."""
    configuration = plan.get("configuration")
    module = configuration.get("root_module") if isinstance(configuration, Mapping) else None
    expressions: dict[str, Mapping[str, Any]] = {}
    for resource in _module_resources(module):
        address = resource.get("address")
        found = resource.get("expressions")
        if isinstance(address, str):
            expressions[address] = found if isinstance(found, Mapping) else {}
    return expressions


def module_calls(plan: Mapping[str, Any]) -> list[str]:
    """Return the names of the modules the root configuration calls."""
    configuration = plan.get("configuration")
    module = configuration.get("root_module") if isinstance(configuration, Mapping) else None
    calls = module.get("module_calls") if isinstance(module, Mapping) else None
    return sorted(str(name) for name in calls) if isinstance(calls, Mapping) else []


def references(expression: Any) -> list[str]:
    """Return what one configured expression refers to; empty for a value typed out in full."""
    if not isinstance(expression, Mapping):
        return []
    found = expression.get("references")
    return [str(item) for item in found] if isinstance(found, list) else []


def shape_problems(plan: Mapping[str, Any], expected: Iterable[Expected]) -> list[str]:
    """Return how the planned resources differ from the expected types; empty when they match.

    Every created resource counts, whatever its type, and a module call is a problem of its
    own: a module can create resources this file cannot see by name. The managed resources
    the configuration declares are counted too, so a resource the plan would take over rather
    than create (an ``import``) cannot hide from the count.
    """
    wanted = Counter(item.resource_type for item in expected)
    planned = Counter(item.resource_type for item in created(plan))
    addresses = list(configured(plan))
    declared = Counter(
        address.split(".")[0] for address in addresses if not address.startswith(DATA_PREFIX)
    )
    problems: list[str] = []
    for resource_type in sorted(set(wanted) | set(planned)):
        if planned[resource_type] != wanted[resource_type]:
            problems.append(
                f"{resource_type}: the plan creates {planned[resource_type]}, the stack has "
                f"{wanted[resource_type]}"
            )
    for resource_type in sorted(set(wanted) | set(declared)):
        if declared[resource_type] != wanted[resource_type]:
            problems.append(
                f"{resource_type}: the declarations hold {declared[resource_type]}, the stack "
                f"has {wanted[resource_type]}"
            )
    for name in module_calls(plan):
        problems.append(f"module {name!r}: declare the resources directly, with no module")
    configured_types = {address.removeprefix(DATA_PREFIX).split(".")[0] for address in addresses}
    if SECRET_VERSION_TYPE in configured_types:
        problems.append(f"a {SECRET_VERSION_TYPE} is declared or read")
    return problems


def plan_block_problems(plan: Mapping[str, Any]) -> list[str]:
    """Return each provisioner, provider configuration, import or removal the plan holds.

    providers.tf supplies the one provider configuration the run needs; another one (an
    alias, say) could point somewhere else, and a provisioner runs a command of its own. An
    ``import`` block takes over a resource that already exists, and a ``removed`` block lets
    go of one, so neither is a resource the declarations create.
    """
    problems: list[str] = []
    for change in plan.get("resource_changes") or []:
        details = change.get("change") if isinstance(change, Mapping) else None
        if not isinstance(details, Mapping):
            continue
        actions = details.get("actions")
        if details.get("importing"):
            problems.append(f"{change.get('address')}: declare no import block")
        if isinstance(actions, list) and "forget" in actions:
            problems.append(f"{change.get('address')}: declare no removed block")
    configuration = plan.get("configuration")
    if not isinstance(configuration, Mapping):
        return problems
    providers = configuration.get("provider_config")
    if isinstance(providers, Mapping):
        for name in sorted(str(item) for item in providers):
            if name not in SUPPLIED_PROVIDER_CONFIGS:
                problems.append(f"provider configuration {name!r}: use only the supplied one")
    for resource in _module_resources(configuration.get("root_module")):
        if resource.get("provisioners"):
            problems.append(f"{resource.get('address')}: declare no provisioner")
    return problems


def forbidden_block_problems(root: Path) -> list[str]:
    """Return each block your declarations may not hold, by file and line.

    Every ``.tf`` or ``.tf.json`` file under infra/tofu/ besides the supplied ``providers.tf``
    and ``variables.tf`` is read: a ``terraform``, ``backend``, ``cloud``, ``provider``,
    ``module``, ``provisioner``, ``connection``, ``import`` or ``removed`` block there is a
    problem, because it changes where the state goes, what OpenTofu talks to, what it runs, or
    which existing resources it takes over or lets go of.
    """
    problems: list[str] = []
    for path in _declaration_files(root):
        relative = path.relative_to(root).as_posix()
        text = _read(path)
        pattern = FORBIDDEN_JSON_KEY if path.name.endswith(".tf.json") else FORBIDDEN_BLOCK
        for found in pattern.finditer(text):
            line = text.count("\n", 0, found.start()) + 1
            problems.append(f"{relative}:{line} holds a `{found.group(1)}` block")
    return problems


def inline_ignore_problems(root: Path) -> list[str]:
    """Return each line of your declarations that carries an inline scanner ignore.

    Trivy honours a ``trivy:ignore`` (or ``tfsec:ignore``) comment in both of ``poe verify``'s
    scans, so it would hide a finding without an entry in infra/tofu/.trivyignore: it is
    never a fix and never an accept.
    """
    problems: list[str] = []
    for path in _declaration_files(root, supplied=True):
        relative = path.relative_to(root).as_posix()
        for number, line in enumerate(_read(path).splitlines(), start=1):
            if INLINE_IGNORE.search(line):
                problems.append(
                    f"{relative}:{number} carries an inline scanner ignore; accept only through "
                    f"{tofu.TOFU_DIRECTORY.as_posix()}/{tofu.IGNORE_FILE}"
                )
    return problems


def _declaration_files(root: Path, *, supplied: bool = False) -> list[Path]:
    """Return the ``.tf`` and ``.tf.json`` files under infra/tofu/, the supplied ones if asked."""
    return [
        path
        for path in configuration_files(root)
        if path.name.endswith(tofu.CONFIG_SUFFIXES)
        and (supplied or path.name not in tofu.SUPPLIED_FILES)
    ]


def _read(path: Path) -> str:
    """Return a file's text, or an empty text when it cannot be read as UTF-8."""
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


def match_resource(plan: Mapping[str, Any], item: Expected, prefix: str) -> Planned | None:
    """Return the created resource of ``item``'s type named from ``prefix`` and its stack name."""
    for planned in created(plan):
        if planned.resource_type != item.resource_type or planned.name is None:
            continue
        if infra_diff.rest_of(planned.name, prefix) == item.rest:
            return planned
    return None


def naming_problems(
    plan: Mapping[str, Any], expected: Iterable[Expected], prefix: str
) -> list[str]:
    """Return each expected resource that is not created under its name from the prefix.

    The planned name must be the prefix, one separator (``-`` or ``/``) and the stack name
    after ``coldline`` and its separator. ``poe verify`` passes a prefix of its own, new each
    run, so only a name built from ``var.name_prefix`` (directly or through a ``locals``
    value) can match it.
    """
    problems: list[str] = []
    for item in expected:
        if match_resource(plan, item, prefix) is None:
            problems.append(
                f"the {item.role}: no {item.resource_type} is named {prefix}-{item.rest} "
                f"(or {prefix}/{item.rest}) under the prefix {prefix}"
            )
    return problems


def redrive_problems(
    plan: Mapping[str, Any], names: infra_diff.StackNames, prefix: str
) -> list[str]:
    """Return why the queue's redrive policy does not refer to the dead-letter queue resource.

    The queue's ``redrive_policy`` expression must list the dead-letter queue resource's
    ``arn`` attribute among its references, and refer to nothing else: a dead-letter queue ARN
    typed out as text is a constant, which OpenTofu cannot track as a dependency, and one built
    from a variable or a ``locals`` value is the same text with a placeholder in it.
    """
    queue_item, dead_letter_item = expected_resources(names)[1:3]
    queue = match_resource(plan, queue_item, prefix)
    dead_letter = match_resource(plan, dead_letter_item, prefix)
    if queue is None or dead_letter is None:
        return ["declare the queue and the dead-letter queue, both named from the prefix"]
    settings = configured(plan).get(config_address(queue.address), {})
    target = config_address(dead_letter.address)
    referred = references(settings.get("redrive_policy"))
    others = [
        reference
        for reference in referred
        if config_address(reference.removesuffix(".arn")) != target
    ]
    by_reference = any(
        reference.endswith(".arn") and reference not in others for reference in referred
    )
    if others:
        return [
            f"{queue.address}: its redrive_policy refers to {', '.join(others)}; refer only to "
            f"{target}.arn and write maxReceiveCount as a number"
        ]
    if by_reference:
        return []
    if not referred:
        return [
            f"{queue.address}: its redrive_policy refers to nothing; set deadLetterTargetArn to "
            f"{target}.arn"
        ]
    return [
        f"{queue.address}: its redrive_policy refers to {', '.join(referred)}, not to {target}.arn"
    ]


def configuration_files(root: Path) -> list[Path]:
    """Return the files under infra/tofu/ a pull request would carry: tracked or not ignored."""
    directory = tofu.TOFU_DIRECTORY.as_posix() + "/"
    listed = repository.listed_files(root)
    if listed is not None:
        return [
            root / path for path in listed if path.startswith(directory) and (root / path).is_file()
        ]
    found: list[Path] = []
    for path in sorted((root / tofu.TOFU_DIRECTORY).rglob("*")):
        relative = path.relative_to(root / tofu.TOFU_DIRECTORY)
        if not path.is_file() or ".terraform" in relative.parts or ".tfstate" in path.name:
            continue
        found.append(path)
    return found


def secret_problems(root: Path) -> list[str]:
    """Return each file under infra/tofu/ that declares a secret version or holds a secret value.

    The values looked for are the provider secret's first version and any key in the Coldline
    provider-key format (the format ``poe secret-replace`` generates and the supplied Gitleaks
    rule matches). A finding names the file and what was found in it, never the value.
    """
    problems: list[str] = []
    for path in configuration_files(root):
        relative = path.relative_to(root).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if SECRET_VERSION_BLOCK.search(text):
            problems.append(f"{relative} declares an {SECRET_VERSION_TYPE}")
        if FIRST_VERSION_VALUE in text:
            problems.append(f"{relative} holds the provider secret's first version")
        if seeds.matches_supplied_rule(text):
            problems.append(f"{relative} holds a key in the Coldline provider-key format")
    return problems


__all__ = [
    "Expected",
    "Planned",
    "config_address",
    "configuration_files",
    "configured",
    "created",
    "expected_resources",
    "forbidden_block_problems",
    "inline_ignore_problems",
    "match_resource",
    "module_calls",
    "naming_problems",
    "plan_block_problems",
    "redrive_problems",
    "references",
    "secret_problems",
    "shape_problems",
]
