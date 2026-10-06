"""Coldline.

===================

File:              tests/unit/security/test_runtime_logs.py
Component:         Unit tests — Redacted runtime logs
Purpose:           Prove the hosted jobs' log renderer replaces every stored version's value with
                    its version id, withholds the logs when the versions cannot be read, and says
                    so when no container exists.
Interacts With:    tests/security/runtime_logs.py, tests/security/secret_tools.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          Logs as evidence of a failure, never of a value
Tools:             Python 3.12, pytest

The values here are synthetic; the outcome of every search for one is computed before it
is asserted, so a failing assertion renders no log text.
"""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from pathlib import Path

import pytest

from adapters.secrets import SecretUnavailable, SecretVersion
from tests.security import runtime_logs

VERSIONS = [
    (SecretVersion("version-1", "000000000001", ("AWSPREVIOUS",)), "unit-value-one"),
    (SecretVersion("version-2", "000000000002", ("AWSCURRENT",)), "unit-value-one-longer"),
]
LOG = (
    "worker  | authenticated with unit-value-one-longer after unit-value-one\n"
    "worker  | version version-2 accepted\n"
)


class ScriptedCompose:
    """Answer the Compose commands the renderer makes, and keep them."""

    def __init__(
        self, *, containers: bool = True, services: Sequence[str] = ("worker", "localstack")
    ):
        """Script which containers and services the fake Compose reports."""
        self.containers = containers
        self.services = list(services)
        self.commands: list[list[str]] = []

    def __call__(self, arguments: Sequence[str]) -> subprocess.CompletedProcess[str]:
        """Script one command."""
        self.commands.append(list(arguments))
        if arguments[:3] == ["ps", "--all", "--quiet"]:
            return subprocess.CompletedProcess(arguments, 0, "abc123\n" if self.containers else "")
        if arguments[:2] == ["ps", "--all"]:
            return subprocess.CompletedProcess(arguments, 0, "NAME  STATUS\nworker  exited\n", "")
        if arguments[:2] == ["config", "--services"]:
            return subprocess.CompletedProcess(arguments, 0, "\n".join(self.services) + "\n", "")
        if arguments[0] == "logs":
            return subprocess.CompletedProcess(arguments, 0, LOG, "")
        raise AssertionError(f"unexpected compose command {arguments}")


def test_every_stored_value_is_replaced_by_its_version_id_longest_first() -> None:
    """A value that is a prefix of another leaves no tail behind; ids name the versions."""
    rendered = runtime_logs.redact(LOG, VERSIONS)

    assert "[provider-key version version-2]" in rendered
    assert "[provider-key version version-1]" in rendered
    leaked = any(value in rendered for _, value in VERSIONS)
    assert not leaked, "a stored value survived the redaction"
    assert rendered.endswith("version version-2 accepted\n")
    assert runtime_logs.redact("nothing here", VERSIONS) == "nothing here"
    assert runtime_logs.redact(LOG, [(VERSIONS[0][0], "")]) == LOG, "an empty value is skipped"


def test_the_rendered_logs_hold_every_service_in_a_group_and_no_value(tmp_path: Path) -> None:
    """One group per service, the main services with the deeper tail, every value redacted."""
    compose = ScriptedCompose()

    code, lines = runtime_logs.render(
        runner=compose, read_versions=lambda root: VERSIONS, root=tmp_path
    )

    assert code == 0
    text = "\n".join(lines)
    assert "::group::worker logs (last 2000 lines at most, provider-key redacted)" in text
    assert "::group::localstack logs (last 200 lines at most, provider-key redacted)" in text
    assert text.count("::endgroup::") == 2
    assert "[provider-key version version-2]" in text
    leaked = any(value in text for _, value in VERSIONS)
    assert not leaked, "a stored value reached the rendered logs"
    tails = [command for command in compose.commands if command[0] == "logs"]
    assert [command[command.index("--tail") + 1] for command in tails] == ["2000", "200"]
    # The versions were read before any log was: the first log command comes after `ps`.
    assert compose.commands[0] == ["ps", "--all", "--quiet"]


@pytest.mark.parametrize(
    "error",
    [SecretUnavailable("the store is unreachable"), OSError("no route"), ConnectionError("x")],
    ids=["store", "os", "connection"],
)
def test_logs_are_withheld_with_a_diagnostic_when_the_versions_cannot_be_read(
    tmp_path: Path, error: Exception
) -> None:
    """No versions, no logs: a diagnostic names the error's kind and nothing else is printed."""
    compose = ScriptedCompose()

    def failing(root: Path) -> list[tuple[SecretVersion, str]]:
        raise error

    code, lines = runtime_logs.render(runner=compose, read_versions=failing, root=tmp_path)

    assert code == 2
    [line] = lines
    assert line.startswith(runtime_logs.WITHHELD) and type(error).__name__ in line
    assert not any(command[0] == "logs" for command in compose.commands), "no log was read"


def test_no_container_is_said_so_without_reading_the_store(tmp_path: Path) -> None:
    """A job that failed before the runtime started has nothing to show, and reads nothing."""
    compose = ScriptedCompose(containers=False)

    def never(root: Path) -> list[tuple[SecretVersion, str]]:
        raise AssertionError("the store must not be read when there is no container")

    assert runtime_logs.render(runner=compose, read_versions=never, root=tmp_path) == (
        0,
        [runtime_logs.NO_CONTAINERS],
    )


def test_the_command_line_prints_the_lines_and_exits_with_the_verdict(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Exit 0 with the redacted groups on stdout; exit 2 with the diagnostic on stderr."""
    monkeypatch.setattr(runtime_logs, "run_compose", ScriptedCompose())
    monkeypatch.setattr(runtime_logs, "stored_versions", lambda root: VERSIONS)
    assert runtime_logs.main(["--root", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "::group::worker logs" in out and "[provider-key version version-1]" in out
    leaked = any(value in out for _, value in VERSIONS)
    assert not leaked

    def failing(root: Path) -> list[tuple[SecretVersion, str]]:
        raise SecretUnavailable("down")

    monkeypatch.setattr(runtime_logs, "stored_versions", failing)
    assert runtime_logs.main(["--root", str(tmp_path)]) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and runtime_logs.WITHHELD in captured.err
