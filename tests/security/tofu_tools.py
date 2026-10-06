"""Coldline.

===================

File:              tests/security/tofu_tools.py
Component:         Infrastructure tooling — `poe tofu-plan`, `poe tofu-apply`, `poe tofu-destroy`,
                    `poe tofu-setup`
Purpose:           Run OpenTofu over infra/tofu/ against the stack's LocalStack with the
                    `coldline-sandbox` prefix, and prepare the pinned images and provider once.
Interacts With:    tests/security/tofu.py, infra/tofu/, infra/opentofu.yaml,
                    security/scanners.yaml, pyproject.toml, .github/workflows/task.yml
Sprint/Task:       Sprint 4 — Project 4 / Task 4.10
Concepts:          Plan before apply, a sandbox beside the running stack, state you can throw away
Tools:             Python 3.12, Docker, OpenTofu

``plan``, ``apply`` and ``destroy`` start the pinned OpenTofu image on the stack's Compose
network with ``infra/tofu/`` as the working directory and ``coldline-sandbox`` as the name
prefix. Each runs ``tofu init`` first (quietly, from the lock file; its output is shown only
when it fails), then the command itself, whose output you read as it runs: the plan and its
summary line, or what was created or destroyed. ``apply`` and ``destroy`` pass
``-auto-approve``: the plan they show is the one they carry out. OpenTofu's state file and its
``.terraform/`` directory are written beside your declarations, in ``infra/tofu/``, and Git
ignores both.

``setup`` is the one network step, done once before the others: it pulls the pinned OpenTofu
and Trivy images and downloads the provider the lock file pins into ``.tools/tofu-plugins/``.
It needs no running stack, and running it again changes nothing. ``plan``, ``apply`` and
``destroy`` (like ``poe tofu-scan`` and ``poe verify``) check that it has run and stop with a
message naming ``poe tofu-setup`` when the image or the provider is missing.

Exit 0 when OpenTofu succeeded, 1 when it reported a failure, 2 when it could not run.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

from tests.security import iac_run, scanners, tofu

TASK_ROOT = Path(__file__).resolve().parents[2]
# The saved plan `poe tofu-apply` checks before it applies; Git-ignored with the state.
SANDBOX_PLAN = "sandbox.tfplan"
COMMANDS: dict[str, tuple[str, ...]] = {
    "plan": ("plan", "-input=false", "-no-color"),
    "apply": ("apply", "-input=false", "-no-color", "-auto-approve"),
    "destroy": ("destroy", "-input=false", "-no-color", "-auto-approve"),
}
SETUP = "setup"


def setup(root: Path = TASK_ROOT) -> int:
    """Pull the pinned OpenTofu and Trivy images and cache the provider the lock file pins."""
    pin = tofu.load_pin(root)
    trivy = scanners.load_pins(root).scanners["trivy"]
    for reference in (pin.reference, trivy.reference):
        pulled = tofu.run_command(["docker", "pull", "--quiet", reference], True)
        if pulled.returncode != 0:
            detail = tofu.tail(tofu.output_of(pulled))
            raise tofu.TofuError(f"{reference} could not be pulled: {detail}")
        print(f"tofu-setup: image present: {reference}")
    with tempfile.TemporaryDirectory(prefix="coldline-tofu-setup-") as temporary:
        work = Path(temporary)
        source = root / tofu.TOFU_DIRECTORY
        for name in tofu.SUPPLIED_FILES:
            (work / name).write_bytes((source / name).read_bytes())
        command = tofu.Tofu(tofu.Workspace(work, tofu.SANDBOX_PREFIX, None), root=root, pin=pin)
        initialized = command.init()
    if initialized.returncode != 0:
        print("tofu-setup: `tofu init` failed:", file=sys.stderr)
        print(tofu.tail(tofu.output_of(initialized)), file=sys.stderr)
        return 1
    print(
        f"tofu-setup: the provider infra/tofu/{tofu.LOCK_FILE} pins is cached in "
        f"{tofu.PLUGIN_CACHE.as_posix()}/"
    )
    return 0


def run(command: str, root: Path = TASK_ROOT) -> int:
    """Initialize infra/tofu/ from the lock file, then run one OpenTofu command, printing it."""
    pin = tofu.load_pin(root)
    missing = tofu.setup_problem(root, [pin.reference])
    if missing is not None:
        raise tofu.TofuError(missing)
    network = tofu.localstack_network(root)
    workspace = tofu.Workspace(root / tofu.TOFU_DIRECTORY, tofu.SANDBOX_PREFIX, network)
    runner = tofu.Tofu(workspace, root=root, pin=pin)
    print(
        f"tofu-{command}: OpenTofu {runner.pin.version} in infra/tofu/, prefix "
        f"{tofu.SANDBOX_PREFIX}, state infra/tofu/{tofu.STATE_FILE}, LocalStack on {network}",
        flush=True,
    )
    initialized = runner.init()
    if initialized.returncode != 0:
        print(f"tofu-{command}: `tofu init` failed:", file=sys.stderr)
        print(tofu.tail(tofu.output_of(initialized)), file=sys.stderr)
        return 1
    if command == "apply":
        return _guarded_apply(runner, root)
    completed = runner.run(*COMMANDS[command], capture=False)
    return 0 if completed.returncode == 0 else 1


def _guarded_apply(runner: tofu.Tofu, root: Path) -> int:
    """Plan to a file, refuse a plan that would reach past the sandbox, then apply that plan.

    A resource named without the ``coldline-sandbox`` prefix could be one of the stack's own
    resources; applying would take it into the sandbox state and `poe tofu-destroy` would
    then delete it, so such a plan is refused before anything changes.
    """
    planned = runner.run("plan", "-input=false", "-no-color", f"-out={SANDBOX_PLAN}", capture=False)
    if planned.returncode != 0:
        return 1
    problems = iac_run.apply_problems(root, runner.show_json(SANDBOX_PLAN), tofu.SANDBOX_PREFIX)
    if problems:
        print("tofu-apply: not applied:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    applied = runner.run("apply", "-input=false", "-no-color", SANDBOX_PLAN, capture=False)
    return 0 if applied.returncode == 0 else 1


def main(argv: list[str] | None = None) -> int:
    """Run one of the sandbox commands, or prepare the images and the provider."""
    parser = argparse.ArgumentParser(
        description="Run OpenTofu over infra/tofu/ against LocalStack with the sandbox prefix."
    )
    parser.add_argument("command", choices=(*COMMANDS, SETUP))
    parser.add_argument("--root", type=Path, default=TASK_ROOT)
    arguments = parser.parse_args(argv)
    root = arguments.root.resolve()
    try:
        if arguments.command == SETUP:
            return setup(root)
        return run(arguments.command, root)
    except (tofu.TofuError, scanners.ScanError, OSError) as exc:
        print(f"tofu-{arguments.command}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
