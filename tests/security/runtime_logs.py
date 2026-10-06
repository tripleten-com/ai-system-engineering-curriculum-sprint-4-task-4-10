"""Coldline.

===================

File:              tests/security/runtime_logs.py
Component:         Security tooling — Redacted runtime logs for a failed hosted run
Purpose:           Print the runtime containers' logs after a failed or cancelled hosted job with
                    every stored version of the provider key replaced by its version id, or
                    withhold the logs when the versions cannot be read.
Interacts With:    .github/workflows/task.yml (`poe runtime-logs`), tests/security/secret_tools.py,
                    src/adapters/secrets/localstack.py, compose.yaml, pyproject.toml
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          Logs as evidence of a failure, never of a value; fail closed when the
                    redaction cannot be made
Tools:             Python 3.12, Docker Compose, LocalStack

The hosted `verify` and `reliability-gate` jobs print the runtime containers' logs when
they fail, so a startup failure leaves its reason behind. A settings module that logs the
key, or a worker that prints what it presented, would put a version's value into that
output, on a page every collaborator of the repository can read, right after the assessed
row reported the leak by version id. So the workflows never print `docker compose logs`
raw: this renderer reads every version the store holds (through the same supplied adapter
the tools use, on the published LocalStack port), replaces each value in each service's
log text with ``[provider-key version <id>]`` (longest value first, so one value that is a
prefix of another cannot leave a tail behind) and prints the result in one group per
service. When the versions cannot be read (the store is down, the secret is absent, the
port is wrong) it prints a diagnostic and withholds the logs, because an unredacted log is
worse than no log. When no runtime container exists it says so and exits 0.

Nothing here reads a value from a log or prints one: the values are read from the store
into this process and leave it only as the placeholder.
"""

from __future__ import annotations

import argparse
import asyncio
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from adapters.secrets import PROVIDER_KEY_SECRET_NAME, SecretUnavailable, SecretVersion
from tests.security import secret_tools

TASK_ROOT = secret_tools.TASK_ROOT
COMPOSE = secret_tools.COMPOSE
PLACEHOLDER = "[provider-key version {version_id}]"
# The services whose logs are shown in full depth; every other service shows a short tail.
MAIN_SERVICES: frozenset[str] = frozenset({"initializer", "api", "worker"})
MAIN_TAIL = 2000
OTHER_TAIL = 200
COMMAND_TIMEOUT_SECONDS = 120
NO_CONTAINERS = "No runtime containers to show."
WITHHELD = (
    "runtime-logs: the provider key's versions could not be read from the store, so the "
    "runtime logs are withheld: they cannot be redacted without them"
)

Runner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]
VersionReader = Callable[[Path], list[tuple[SecretVersion, str]]]


class RuntimeLogsError(RuntimeError):
    """Report that the logs could not be rendered, as opposed to a log line."""


def run_compose(arguments: Sequence[str]) -> subprocess.CompletedProcess[str]:
    """Run one Compose command from the Task root, capturing both streams."""
    return subprocess.run(
        [*COMPOSE, *arguments],
        cwd=TASK_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=COMMAND_TIMEOUT_SECONDS,
        check=False,
    )


def stored_versions(root: Path = TASK_ROOT) -> list[tuple[SecretVersion, str]]:
    """Return every version the store holds with its value, read into this process only."""
    store = secret_tools.host_store(root)
    versions = asyncio.run(store.versions(PROVIDER_KEY_SECRET_NAME))
    return [
        (version, asyncio.run(store.value_of(PROVIDER_KEY_SECRET_NAME, version.version_id)))
        for version in versions
    ]


def redact(text: str, versions: Sequence[tuple[SecretVersion, str]]) -> str:
    """Return ``text`` with every version's value replaced by its placeholder."""
    for version, value in sorted(versions, key=lambda pair: len(pair[1]), reverse=True):
        if value:
            text = text.replace(value, PLACEHOLDER.format(version_id=version.version_id))
    return text


def service_names(runner: Runner) -> list[str]:
    """Return the Compose services, as `compose config --services` lists them."""
    completed = runner(["config", "--services"])
    if completed.returncode != 0:
        raise RuntimeLogsError(f"the Compose services could not be listed: {completed.stderr}")
    return [line.strip() for line in completed.stdout.splitlines() if line.strip()]


def has_containers(runner: Runner) -> bool:
    """Return whether any runtime container exists, running or stopped."""
    completed = runner(["ps", "--all", "--quiet"])
    return completed.returncode == 0 and bool(completed.stdout.strip())


def render(
    *,
    runner: Runner | None = None,
    read_versions: VersionReader | None = None,
    root: Path = TASK_ROOT,
) -> tuple[int, list[str]]:
    """Return the exit code and the lines to print: the redacted logs, or why they are withheld.

    The versions are read before any log is read, so no log text exists in this process
    until the redaction can be made. ``runner`` and ``read_versions`` default to the real
    Compose runner and the store read, looked up when called so a test can replace them.
    """
    runner = run_compose if runner is None else runner
    read_versions = stored_versions if read_versions is None else read_versions
    if not has_containers(runner):
        return 0, [NO_CONTAINERS]
    try:
        versions = read_versions(root)
    except (SecretUnavailable, secret_tools.SecretToolError, OSError) as exc:
        return 2, [f"{WITHHELD} ({type(exc).__name__})"]
    lines: list[str] = []
    listing = runner(["ps", "--all"])
    lines.extend(redact(listing.stdout, versions).splitlines())
    for service in service_names(runner):
        tail = MAIN_TAIL if service in MAIN_SERVICES else OTHER_TAIL
        lines.append(f"::group::{service} logs (last {tail} lines at most, provider-key redacted)")
        logs = runner(["logs", "--no-color", "--timestamps", "--tail", str(tail), service])
        lines.extend(redact(logs.stdout + logs.stderr, versions).splitlines())
        lines.append("::endgroup::")
    return 0, lines


def main(argv: list[str] | None = None) -> int:
    """Print the redacted runtime logs, or the diagnostic that withholds them."""
    parser = argparse.ArgumentParser(
        description=(
            "Print the runtime containers' logs with every stored provider-key version "
            "replaced by its version id; withhold them when the versions cannot be read."
        )
    )
    parser.add_argument("--root", type=Path, default=TASK_ROOT)
    arguments = parser.parse_args(argv)
    try:
        code, lines = render(root=arguments.root)
    except RuntimeLogsError as exc:
        print(f"runtime-logs: {exc}", file=sys.stderr)
        return 2
    stream = sys.stderr if code else sys.stdout
    for line in lines:
        print(line, file=stream)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
