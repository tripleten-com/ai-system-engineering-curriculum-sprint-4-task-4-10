"""Coldline.

===================

File:              tests/security/tofu.py
Component:         Infrastructure tooling — OpenTofu in a pinned container
Purpose:           Run OpenTofu, pinned by digest in infra/opentofu.yaml, against the stack's
                    LocalStack over one working directory with its own state, provider cache
                    and name prefix.
Interacts With:    infra/opentofu.yaml, infra/tofu/, compose.yaml, tests/security/tofu_tools.py,
                    tests/security/iac_run.py, tests/security/tofu_scan.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.10
Concepts:          No host install, a pinned tool image, a provider pinned by its lock file,
                    one state per working directory
Tools:             Python 3.12, Docker, OpenTofu

There is no host install of OpenTofu. Every command runs ``tofu`` inside the image
``infra/opentofu.yaml`` pins, through ``docker run --rm``, with:

- the working directory mounted at ``/work``: ``infra/tofu/`` for your sandbox, a copy under
  ``.tools/tofu-verify/`` for ``poe verify``. The state file and the ``.terraform/`` directory
  OpenTofu writes stay beside the declarations they track, so each working directory has its
  own state;
- the provider cache ``.tools/tofu-plugins/`` mounted at ``/plugins``, so the provider the lock
  file pins is downloaded once and reused by every working directory;
- the Compose network the stack's ``localstack`` container is on, so ``providers.tf`` reaches it
  as ``http://localstack:4566`` whatever host port the stack publishes;
- the name prefix passed as ``TF_VAR_name_prefix``.

``tofu init`` always runs with ``-lockfile=readonly``: the supplied
``infra/tofu/.terraform.lock.hcl`` pins the provider and its checksums, and no command rewrites
it. On POSIX the container runs as the caller's user, so the files it writes are yours.

``poe tofu-setup`` pulls the pinned images and caches the provider once; every other command
checks that it has (``setup_problem``) and stops with a message naming it when it has not.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

TASK_ROOT = Path(__file__).resolve().parents[2]
PIN_PATH = Path("infra/opentofu.yaml")
TOFU_DIRECTORY = Path("infra/tofu")
PLUGIN_CACHE = Path(".tools/tofu-plugins")
SANDBOX_PREFIX = "coldline-sandbox"
# The stack's own resources are named from this; no OpenTofu prefix may equal it.
STACK_PREFIX = "coldline"
LOCK_FILE = ".terraform.lock.hcl"
IGNORE_FILE = ".trivyignore"
STATE_FILE = "terraform.tfstate"
CONFIG_SUFFIXES = (".tf", ".tf.json")
# The supplied files a working copy needs besides your declarations.
SUPPLIED_FILES = ("providers.tf", "variables.tf", LOCK_FILE)
WORKDIR = "/work"
PLUGINS = "/plugins"
COMPOSE_PROFILES: tuple[str, ...] = ("--profile", "observability", "--profile", "localstack")
NETWORK_SUFFIX = "_coldline"
DOCKER_TIMEOUT_SECONDS = 900
INIT_ATTEMPTS = 3
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
UNPINNED_DIGEST = "sha256:" + "0" * 64
SETUP_HINT = "run `poe tofu-setup` once first (it pulls the images and the provider)"
Runner = Callable[[Sequence[str], bool], subprocess.CompletedProcess[str]]


class TofuError(RuntimeError):
    """Report that OpenTofu could not run, as opposed to what it reported when it ran."""


@dataclass(frozen=True)
class TofuPin:
    """The OpenTofu image, pinned by digest, with its version recorded for a reader."""

    image: str
    version: str
    digest: str

    @property
    def reference(self) -> str:
        """Return the reference Docker pulls: the digest, with the tag beside it."""
        return f"{self.image}:{self.version}@{self.digest}"


def load_pin(root: Path = TASK_ROOT) -> TofuPin:
    """Read infra/opentofu.yaml, refusing an image that is not pinned by a real digest."""
    label = PIN_PATH.as_posix()
    try:
        document = yaml.safe_load((root / PIN_PATH).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise TofuError(f"{label} could not be read: {exc}") from exc
    entry = document.get("opentofu") if isinstance(document, dict) else None
    if not isinstance(entry, dict):
        raise TofuError(f"{label} must hold one `opentofu` mapping")
    image, version, digest = entry.get("image"), entry.get("version"), entry.get("digest")
    if not all(isinstance(value, str) and value for value in (image, version, digest)):
        raise TofuError(f"{label}: `opentofu` needs image, version and digest")
    if not DIGEST.match(str(digest)) or digest == UNPINNED_DIGEST:
        raise TofuError(f"{label}: the OpenTofu image is not pinned by a real sha256 digest")
    return TofuPin(str(image), str(version), str(digest))


def user_flags() -> list[str]:
    """Return ``--user uid:gid`` on POSIX, so the files a container writes are the caller's."""
    getuid = getattr(os, "getuid", None)
    getgid = getattr(os, "getgid", None)
    if getuid is None or getgid is None:
        return []
    return ["--user", f"{getuid()}:{getgid()}"]


def run_command(arguments: Sequence[str], capture: bool) -> subprocess.CompletedProcess[str]:
    """Run one command; capture its output, or let it print as it runs."""
    command = list(arguments)
    try:
        return subprocess.run(
            command,
            capture_output=capture,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=DOCKER_TIMEOUT_SECONDS,
        )
    except FileNotFoundError as exc:
        raise TofuError(f"{command[0]} is not on PATH; OpenTofu runs through Docker") from exc
    except subprocess.TimeoutExpired as exc:
        raise TofuError(f"{command[0]} did not finish within {DOCKER_TIMEOUT_SECONDS} s") from exc


def digest_reference(reference: str) -> str:
    """Return ``image@digest`` for ``image:tag@digest``: the form a pulled image is found by."""
    name, separator, digest = reference.partition("@")
    if not separator:
        return reference
    head, slash, last = name.rpartition("/")
    return f"{head}{slash}{last.split(':')[0]}@{digest}"


def setup_problem(
    root: Path,
    references: Sequence[str],
    *,
    provider: bool = True,
    runner: Runner = run_command,
) -> str | None:
    """Return what ``poe tofu-setup`` has not prepared yet, or None when everything is there.

    The pinned images must be present in Docker and, unless ``provider`` is False, the
    provider the lock file pins must be in ``.tools/tofu-plugins/``. Nothing is pulled or
    downloaded here.
    """
    for reference in references:
        inspected = runner(["docker", "image", "inspect", digest_reference(reference)], True)
        if inspected.returncode != 0:
            return f"the image {reference} is not present yet; {SETUP_HINT}"
    if provider and not any(path.is_file() for path in (root / PLUGIN_CACHE).rglob("*")):
        return (
            f"the provider infra/tofu/{LOCK_FILE} pins is not in {PLUGIN_CACHE.as_posix()}/ "
            f"yet; {SETUP_HINT}"
        )
    return None


def output_of(completed: subprocess.CompletedProcess[str]) -> str:
    """Return what a captured command printed, standard output first."""
    return f"{completed.stdout or ''}{completed.stderr or ''}"


def tail(text: str, lines: int = 20) -> str:
    """Return the last ``lines`` lines of ``text``."""
    return "\n".join(text.strip().splitlines()[-lines:])


def localstack_network(root: Path = TASK_ROOT, *, runner: Runner = run_command) -> str:
    """Return the Compose network the stack's running ``localstack`` container is attached to."""
    listed = runner(
        [
            "docker",
            "compose",
            "--project-directory",
            str(root),
            *COMPOSE_PROFILES,
            "ps",
            "--quiet",
            "localstack",
        ],
        True,
    )
    containers = [line.strip() for line in (listed.stdout or "").splitlines() if line.strip()]
    if listed.returncode != 0 or not containers:
        raise TofuError(
            "the stack's localstack container is not running; start the stack first "
            "(`poe start`), with the same COLDLINE_*_HOST_PORT overrides as always"
        )
    inspected = runner(["docker", "inspect", containers[0]], True)
    if inspected.returncode != 0:
        raise TofuError(f"docker inspect failed: {tail(output_of(inspected), 5)}")
    try:
        document = json.loads(inspected.stdout or "")
    except ValueError as exc:
        raise TofuError("docker inspect printed no JSON for the localstack container") from exc
    networks = network_names(document)
    preferred = [name for name in networks if name.endswith(NETWORK_SUFFIX)]
    if len(preferred) == 1:
        return preferred[0]
    if len(networks) == 1:
        return networks[0]
    raise TofuError(f"the localstack container's network is ambiguous: {networks}")


def network_names(document: Any) -> list[str]:
    """Return the network names ``docker inspect`` lists for its first container."""
    if not isinstance(document, list) or not document or not isinstance(document[0], dict):
        return []
    settings = document[0].get("NetworkSettings")
    networks = settings.get("Networks") if isinstance(settings, dict) else None
    if not isinstance(networks, dict):
        return []
    return sorted(str(name) for name in networks)


@dataclass(frozen=True)
class Workspace:
    """One OpenTofu working directory: its declarations, its state, and its name prefix.

    ``network`` is the Compose network to join; None runs on Docker's default network, which
    is enough for ``tofu init`` and nothing that reaches LocalStack.
    """

    directory: Path
    prefix: str
    network: str | None


def tofu_arguments(
    pin: TofuPin, workspace: Workspace, root: Path, arguments: Sequence[str]
) -> list[str]:
    """Return the ``docker run`` command that runs ``tofu`` with ``arguments`` in ``workspace``."""
    network = ["--network", workspace.network] if workspace.network else []
    return [
        "docker",
        "run",
        "--rm",
        *user_flags(),
        *network,
        "-v",
        f"{workspace.directory.resolve()}:{WORKDIR}",
        "-v",
        f"{(root / PLUGIN_CACHE).resolve()}:{PLUGINS}",
        "-w",
        WORKDIR,
        "-e",
        f"TF_PLUGIN_CACHE_DIR={PLUGINS}",
        "-e",
        "TF_IN_AUTOMATION=1",
        "-e",
        "TF_INPUT=0",
        "-e",
        "CHECKPOINT_DISABLE=1",
        "-e",
        "HOME=/tmp",
        "-e",
        f"TF_VAR_name_prefix={workspace.prefix}",
        "--entrypoint",
        "tofu",
        pin.reference,
        *arguments,
    ]


class Tofu:
    """Run OpenTofu commands over one workspace."""

    def __init__(
        self,
        workspace: Workspace,
        *,
        root: Path = TASK_ROOT,
        pin: TofuPin | None = None,
        runner: Runner = run_command,
    ) -> None:
        """Bind the commands to one workspace, the pinned image, and a command runner."""
        if workspace.prefix == STACK_PREFIX:
            raise TofuError("the prefix must not be the stack's own `coldline`")
        self._workspace = workspace
        self._root = root
        self._pin = load_pin(root) if pin is None else pin
        self._runner = runner

    @property
    def workspace(self) -> Workspace:
        """Return the workspace these commands run in."""
        return self._workspace

    @property
    def pin(self) -> TofuPin:
        """Return the pinned OpenTofu image."""
        return self._pin

    def run(self, *arguments: str, capture: bool = True) -> subprocess.CompletedProcess[str]:
        """Run ``tofu`` with ``arguments`` in the workspace."""
        (self._root / PLUGIN_CACHE).mkdir(parents=True, exist_ok=True)
        command = tofu_arguments(self._pin, self._workspace, self._root, arguments)
        return self._runner(command, capture)

    def init(self) -> subprocess.CompletedProcess[str]:
        """Initialize the workspace from the lock file, retrying a failed provider download."""
        completed = self.run("init", "-input=false", "-no-color", "-lockfile=readonly")
        for _ in range(INIT_ATTEMPTS - 1):
            if completed.returncode == 0:
                break
            completed = self.run("init", "-input=false", "-no-color", "-lockfile=readonly")
        return completed

    def show_json(self, plan_file: str) -> dict[str, Any]:
        """Return a saved plan as the JSON ``tofu show -json`` prints."""
        completed = self.run("show", "-json", "-no-color", plan_file)
        if completed.returncode != 0:
            raise TofuError(f"tofu show failed: {tail(output_of(completed), 10)}")
        try:
            document = json.loads(completed.stdout or "")
        except ValueError as exc:
            raise TofuError("tofu show printed no JSON") from exc
        if not isinstance(document, dict):
            raise TofuError("tofu show printed JSON that is not an object")
        return document

    def state_list(self) -> list[str]:
        """Return the addresses the workspace's state tracks."""
        completed = self.run("state", "list", "-no-color")
        if completed.returncode != 0:
            raise TofuError(f"tofu state list failed: {tail(output_of(completed), 10)}")
        return [line.strip() for line in (completed.stdout or "").splitlines() if line.strip()]


def planned_addresses(plan: dict[str, Any], action: str) -> list[str]:
    """Return the managed resources a plan would ``action`` (``create`` or ``delete``)."""
    changes = plan.get("resource_changes")
    addresses: list[str] = []
    for change in changes if isinstance(changes, list) else []:
        if not isinstance(change, dict) or change.get("mode") != "managed":
            continue
        details = change.get("change")
        actions = details.get("actions") if isinstance(details, dict) else None
        if isinstance(actions, list) and action in actions:
            addresses.append(str(change.get("address", "")))
    return addresses


def copy_configuration(source: Path, destination: Path) -> list[str]:
    """Copy the declarations, the lock file and the ignore file of ``source``; return the names.

    Top-level files only, and never what OpenTofu writes: no ``.terraform/`` directory, no
    state, no plan file.
    """
    destination.mkdir(parents=True, exist_ok=True)
    copied: list[str] = []
    for path in sorted(source.iterdir()):
        if not path.is_file():
            continue
        if path.name.endswith(CONFIG_SUFFIXES) or path.name in (LOCK_FILE, IGNORE_FILE):
            shutil.copy2(path, destination / path.name)
            copied.append(path.name)
    return copied


__all__ = [
    "IGNORE_FILE",
    "LOCK_FILE",
    "PLUGIN_CACHE",
    "SANDBOX_PREFIX",
    "STACK_PREFIX",
    "STATE_FILE",
    "SUPPLIED_FILES",
    "TOFU_DIRECTORY",
    "Tofu",
    "TofuError",
    "TofuPin",
    "Workspace",
    "copy_configuration",
    "digest_reference",
    "load_pin",
    "localstack_network",
    "network_names",
    "output_of",
    "planned_addresses",
    "run_command",
    "setup_problem",
    "tail",
    "tofu_arguments",
    "user_flags",
]
