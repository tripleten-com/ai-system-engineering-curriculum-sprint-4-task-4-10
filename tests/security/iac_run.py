"""Coldline.

===================

File:              tests/security/iac_run.py
Component:         Infrastructure tooling — The run `poe verify` observes
Purpose:           Plan, apply, compare, destroy and plan again, with a prefix and an OpenTofu
                    state of its own, scan the declarations, and record what each step observed.
Interacts With:    tests/security/tofu.py, tests/security/infra_diff.py,
                    tests/security/tofu_scan.py, tests/contract/test_iac_contract.py, infra/tofu/
Sprint/Task:       Sprint 4 — Project 4 / Task 4.10
Concepts:          A repeatable rebuild, a check that runs beside your sandbox and never in it
Tools:             Python 3.12, Docker, OpenTofu, Trivy, LocalStack

``observe`` runs the sequence the Task's public command describes, once, and returns what it
saw; the assessed rows in ``tests/contract/test_iac_contract.py`` compare the answer sheet and
the declarations with it.

**Its own prefix and its own state.** The declarations, the lock file and the ignore file are
copied from ``infra/tofu/`` into ``.tools/tofu-verify/work/`` (Git-ignored), and OpenTofu runs
there, so its ``.terraform/`` directory, its plan files and its state never mix with yours. The
prefix is ``coldline-verify-`` and six random hex digits, new for every run, so a run never
touches your ``coldline-sandbox`` resources and never collides with a resource an earlier run
left behind (a secret destroyed without ``recovery_window_in_days = 0`` keeps its name for a
while).

**The sequence.** First, the pinned OpenTofu and Trivy images and the provider must be in
place (``poe tofu-setup``); when they are not, every step is recorded as not run, with a
message naming that command. Then ``tofu init`` from the lock file; a saved plan, read as
JSON for what it creates; that plan applied, unless it holds a block the declarations may
not hold or a type the stack doesn't have; ``poe infra-diff``'s comparison with this
run's prefix; a saved destroy plan, read for what it deletes, then applied; the state
listed, which must then be empty; and a new saved plan, read for what it would create
again. A step that fails is recorded and the steps that need it are skipped; a run that
applied anything destroys what it created before it returns. Last, the configuration scan
reads the copied declarations twice, with your ignore file and with an empty one; it reads
files only, so its place in the sequence changes nothing it reports.
"""

from __future__ import annotations

import contextlib
import secrets
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tests.security import iac_checks, infra_diff, scanners, tofu, tofu_scan

TASK_ROOT = Path(__file__).resolve().parents[2]
VERIFY_DIRECTORY = Path(".tools/tofu-verify")
WORK = "work"
PREFIX_RECORD = "prefix.txt"
PREFIX_BASE = "coldline-verify"
PREFIX_BYTES = 3
ADD_PLAN = "verify-add.tfplan"
DESTROY_PLAN = "verify-destroy.tfplan"
AGAIN_PLAN = "verify-again.tfplan"
PLAN = ("plan", "-input=false", "-no-color")
APPLY = ("apply", "-input=false", "-no-color")
DESTROY = ("destroy", "-input=false", "-no-color", "-auto-approve")


def new_prefix() -> str:
    """Return a prefix no earlier run used: ``coldline-verify-`` and six random hex digits."""
    return f"{PREFIX_BASE}-{secrets.token_hex(PREFIX_BYTES)}"


@dataclass
class Observation:
    """What one run observed at each step, or why a step could not run."""

    prefix: str
    plan: dict[str, Any] | None = None
    plan_error: str = ""
    apply_attempted: bool = False
    applied: bool = False
    apply_error: str = ""
    comparison: infra_diff.Comparison | None = None
    comparison_error: str = ""
    ignore_entries: list[tofu_scan.IgnoreEntry] = field(default_factory=list)
    scan_ignored: tofu_scan.ScanResult | None = None
    scan_unignored: tofu_scan.ScanResult | None = None
    scan_error: str = ""
    destroy_plan: dict[str, Any] | None = None
    destroyed: bool = False
    destroy_error: str = ""
    state_after_destroy: list[str] | None = None
    replan: dict[str, Any] | None = None
    replan_error: str = ""

    @property
    def planned_adds(self) -> int | None:
        """Return how many resources the first plan would add, or None when it did not run."""
        if self.plan is None:
            return None
        return len(tofu.planned_addresses(self.plan, "create"))

    @property
    def destroy_count(self) -> int | None:
        """Return how many resources the destroy deleted, or None when it did not complete."""
        if self.destroy_plan is None or not self.destroyed:
            return None
        return len(tofu.planned_addresses(self.destroy_plan, "delete"))

    @property
    def replanned_adds(self) -> int | None:
        """Return how many resources the plan after the destroy would add again."""
        if self.replan is None:
            return None
        return len(tofu.planned_addresses(self.replan, "create"))

    def summary(self) -> str:
        """Render what the run observed, one step per line, for a failing row's message."""
        steps = [f"prefix: {self.prefix}"]
        if self.plan is not None:
            steps.append(f"plan: adds {self.planned_adds}")
        else:
            steps.append(f"plan: {self.plan_error or 'not run'}")
        applied = "applied" if self.applied else self.apply_error or "not run"
        steps.append(f"apply: {applied}")
        if self.comparison is not None:
            steps.append(f"comparison: {self.comparison.count} difference(s)")
        else:
            steps.append(f"comparison: {self.comparison_error or 'not run'}")
        if self.destroy_count is not None:
            steps.append(f"destroy: deleted {self.destroy_count}")
        else:
            steps.append(f"destroy: {self.destroy_error or 'not run'}")
        if self.replan is not None:
            steps.append(f"plan again: adds {self.replanned_adds}")
        else:
            steps.append(f"plan again: {self.replan_error or 'not run'}")
        return "\n".join(steps)


def _scan(observation: Observation, work: Path, root: Path, runner: tofu.Runner) -> None:
    """Scan the copied declarations with the copied ignore file and with an empty one."""
    ignore_text = tofu_scan.read_ignore(work)
    observation.ignore_entries = tofu_scan.parse_ignore(ignore_text)
    try:
        observation.scan_ignored = tofu_scan.scan_configuration(
            work, ignore_text, root=root, runner=runner
        )
        observation.scan_unignored = tofu_scan.scan_configuration(
            work, "", root=root, runner=runner
        )
    except (tofu_scan.ScanError, scanners.ScanError, RuntimeError) as exc:
        observation.scan_error = str(exc)


def _setup_problem(root: Path, runner: tofu.Runner) -> str | None:
    """Return why the run cannot start: a pin unreadable, or ``poe tofu-setup`` not yet run."""
    try:
        references = [
            tofu.load_pin(root).reference,
            scanners.load_pins(root).scanners["trivy"].reference,
        ]
    except (tofu.TofuError, scanners.ScanError) as exc:
        return str(exc)
    return tofu.setup_problem(root, references, runner=runner)


def _destroy_leftovers(base: Path, root: Path, network: str, runner: tofu.Runner) -> None:
    """Destroy what an earlier run that never finished left in its state, as far as possible."""
    work = base / WORK
    record = base / PREFIX_RECORD
    if not (work / tofu.STATE_FILE).is_file() or not record.is_file():
        return
    prefix = record.read_text(encoding="utf-8").strip()
    if not prefix or prefix == tofu.STACK_PREFIX:
        return
    try:
        leftover = tofu.Tofu(tofu.Workspace(work, prefix, network), root=root, runner=runner)
        if leftover.init().returncode == 0:
            leftover.run(*DESTROY)
    except tofu.TofuError:
        return


def _failure(step: str, completed: subprocess.CompletedProcess[str]) -> str:
    """Return why one OpenTofu step failed: its exit code and the end of what it printed."""
    printed = tofu.tail(tofu.output_of(completed))
    return f"tofu {step} failed (exit {completed.returncode}): {printed}"


def _destroy_and_plan_again(observation: Observation, command: tofu.Tofu) -> None:
    """Destroy through a saved plan, list the state, and plan again, recording each step."""
    try:
        planned = command.run(*PLAN, "-destroy", f"-out={DESTROY_PLAN}")
        if planned.returncode != 0:
            observation.destroy_error = _failure("plan -destroy", planned)
            return
        observation.destroy_plan = command.show_json(DESTROY_PLAN)
        destroyed = command.run(*APPLY, DESTROY_PLAN)
        observation.destroyed = destroyed.returncode == 0
        if not observation.destroyed:
            observation.destroy_error = _failure("apply (destroy)", destroyed)
            return
        observation.state_after_destroy = command.state_list()
    except tofu.TofuError as exc:
        observation.destroy_error = str(exc)
        return
    try:
        again = command.run(*PLAN, f"-out={AGAIN_PLAN}")
        if again.returncode != 0:
            observation.replan_error = _failure("plan", again)
            return
        observation.replan = command.show_json(AGAIN_PLAN)
    except tofu.TofuError as exc:
        observation.replan_error = str(exc)


def _apply_problems(root: Path, plan: dict[str, Any], prefix: str) -> list[str]:
    """Return why the plan must not be applied: a forbidden block, a type, or a name.

    A provisioner would run a command beside the stack, and a resource of a type the stack
    doesn't have would go to an endpoint the supplied provider doesn't point at LocalStack.
    A resource whose name does not start with ``prefix`` could be the stack's own resource:
    applying would take it into this state, and the destroy that follows would delete it.
    """
    problems = iac_checks.forbidden_block_problems(root) + iac_checks.plan_block_problems(plan)
    for planned in iac_checks.created(plan):
        if planned.resource_type not in iac_checks.NAME_ATTRIBUTE:
            problems.append(f"{planned.address}: the stack has no {planned.resource_type}")
        elif planned.name is None or infra_diff.rest_of(planned.name, prefix) is None:
            problems.append(
                f"{planned.address}: named {planned.name!r}, not from the prefix {prefix}"
            )
    return problems


apply_problems = _apply_problems


def _plan_and_apply(observation: Observation, command: tofu.Tofu, root: Path) -> None:
    """Initialize, plan, apply and compare; then destroy and plan again when the apply held."""
    initialized = command.init()
    if initialized.returncode != 0:
        observation.plan_error = _failure("init", initialized)
        return
    planned = command.run(*PLAN, f"-out={ADD_PLAN}")
    if planned.returncode != 0:
        observation.plan_error = _failure("plan", planned)
        return
    observation.plan = command.show_json(ADD_PLAN)
    refused = _apply_problems(root, observation.plan, observation.prefix)
    if refused:
        observation.apply_error = "not applied: " + "; ".join(refused)
        return
    observation.apply_attempted = True
    applied = command.run(*APPLY, ADD_PLAN)
    observation.applied = applied.returncode == 0
    if not observation.applied:
        observation.apply_error = _failure("apply", applied)
        return
    try:
        observation.comparison = infra_diff.run(root, observation.prefix)
    except (infra_diff.DiffError, ValueError) as exc:
        observation.comparison_error = str(exc)
    _destroy_and_plan_again(observation, command)


def observe(
    root: Path = TASK_ROOT,
    *,
    prefix: str | None = None,
    runner: tofu.Runner = tofu.run_command,
) -> Observation:
    """Run the whole sequence once over a copy of infra/tofu/ and return what it observed."""
    observation = Observation(new_prefix() if prefix is None else prefix)
    missing = _setup_problem(root, runner)
    if missing is not None:
        observation.plan_error = observation.scan_error = missing
        return observation
    base = root / VERIFY_DIRECTORY
    work = base / WORK
    try:
        network = tofu.localstack_network(root, runner=runner)
    except tofu.TofuError as exc:
        # The stack is down: every OpenTofu step is recorded as not run, and the scan still runs.
        observation.plan_error = str(exc)
        _scan(observation, root / tofu.TOFU_DIRECTORY, root, runner)
        return observation
    _destroy_leftovers(base, root, network, runner)
    shutil.rmtree(work, ignore_errors=True)
    tofu.copy_configuration(root / tofu.TOFU_DIRECTORY, work)
    (base / PREFIX_RECORD).write_text(observation.prefix + "\n", encoding="utf-8")
    workspace = tofu.Workspace(work, observation.prefix, network)
    command = tofu.Tofu(workspace, root=root, runner=runner)
    try:
        _plan_and_apply(observation, command, root)
    except tofu.TofuError as exc:
        observation.plan_error = observation.plan_error or str(exc)
    finally:
        # A failed apply can still have created part of the plan: destroy whatever the state holds.
        if observation.apply_attempted and not observation.destroyed:
            with contextlib.suppress(tofu.TofuError):
                command.run(*DESTROY)
    if observation.state_after_destroy == []:
        # Nothing is left to destroy, so the next run needs no clean-up first.
        (base / PREFIX_RECORD).unlink(missing_ok=True)
    _scan(observation, work, root, runner)
    return observation


__all__ = ["Observation", "new_prefix", "observe"]
