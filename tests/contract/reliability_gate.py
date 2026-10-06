"""Coldline.

===================

File:              tests/contract/reliability_gate.py
Component:         Contract tests — CI reliability gate
Purpose:           Statically check the wired reliability-gate job, and live-prove it rejects
                    its own Task's known starting-broken value.
Interacts With:     .github/workflows/task.yml, Docker Compose, LocalStack SQS, Prometheus
Sprint/Task:        Sprint 3 — Project 3
Concepts:           CI reliability gate, assessment integrity, deterministic infrastructure
Tools:              Python 3.12, PyYAML, boto3, Docker Compose, uv

This module is a ``verify()``-style checker in the same spirit as
``tests/contract/slo_alert.py`` and ``tests/contract/runtime_adapters.py``, but it checks a
*CI workflow's own wiring*, not the running application directly. Two things are proven,
independently:

1. **Static** (``static_findings``): the ``reliability-gate`` job in
   ``.github/workflows/task.yml`` exists, triggers on ``pull_request``, carries the same
   export-branch exclusion as the supplied ``verify`` job, no longer runs the supplied
   placeholder step, and its replacement step runs *exactly* ``poe queue-contract`` or
   ``poe slo-contract`` — one command, nothing appended, nothing else substituted.
2. **Live** (``prove_gate_rejects_broken_value``): whichever of the two commands is wired
   actually passes against the current, correctly configured stack, and actually fails once
   the one setting it protects is reverted to *that setting's own Task's* known
   starting-broken value — Task 3.3's ``COLDLINE_QUEUE_MAX_RECEIVE_COUNT=1`` for
   ``queue-contract``, or Task 3.4's ``infra/observability/alerts.yml`` ``for: 90s`` for
   ``slo-contract``. The revert is temporary and always undone, in a ``finally`` block, on
   every exit path — including an assertion failure or an unexpected exception. The queue
   revert never touches a file: ``COLDLINE_QUEUE_MAX_RECEIVE_COUNT`` only matters through the
   *deployed* queue's own ``RedrivePolicy`` attribute (see ``src/adapters/queue/sqs.py``'s
   ``ensure_queue``, which itself converges that attribute idempotently through
   ``set_queue_attributes``), so this reads and writes that attribute directly, the same way
   ``slo_alert.py`` reads the deployed alert rule back from Prometheus's own API rather than
   trusting a file. The alert revert does edit ``infra/observability/alerts.yml`` on disk —
   Prometheus has no live API for a rule's ``for`` duration — so it restores the exact
   original bytes and reloads Prometheus again before returning, leaving the working tree
   byte-identical to how this module found it.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

TASK_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = TASK_ROOT / ".github/workflows/task.yml"
ALERTS_PATH = TASK_ROOT / "infra/observability/alerts.yml"

JOB_NAME = "reliability-gate"
COMPARISON_JOB_NAME = "verify"
PLACEHOLDER_MARKER = "reliability gate placeholder — replace this step"
ALLOWED_COMMANDS = ("queue-contract", "slo-contract")
# Matches the supplied invocation convention (`.tools/bin/uv run --frozen poe <target>`) or a
# bare `poe <target>`, and nothing else on the line: no extra flags, no `&&` chains, no second
# command. `fullmatch` against the stripped line is what makes "exactly" exact.
_RUN_PATTERN = re.compile(r"^(?:\.tools/bin/uv run --frozen )?poe (queue-contract|slo-contract)$")

# Task 3.3's own known starting-broken value: legal against ApiSettings' own bounds, so the
# stack starts, but it gives a delivery zero tolerance for one transient failure.
BROKEN_MAX_RECEIVE_COUNT = 1
# Task 3.4's own known starting-broken value: legal against the published [5s, 120s] bound, so
# Prometheus loads the rule, but it never fires inside this exercise's forced-failure window.
BROKEN_ALERT_FOR = "90s"
PRODUCTION_QUEUE_NAME = "coldline-exception-jobs"


def _load_workflow() -> dict[Any, Any]:
    """Parse the workflow file, tolerating PyYAML's YAML-1.1 `on:` boolean coercion.

    PyYAML's safe loader resolves the bare scalar `on` to the Python boolean `True` (YAML
    1.1's `y|Y|yes|Yes|YES|n|N|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF`
    boolean set), so a workflow's top-level `on:` key comes back as `True`, not `"on"`. Every
    read of the trigger mapping below checks both keys — hence the `dict[Any, Any]` return
    type rather than `dict[str, Any]`.
    """
    loaded: Any = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise AssertionError(f"{WORKFLOW_PATH} does not parse to a YAML mapping")
    return loaded


def _job(workflow: dict[Any, Any], name: str) -> dict[str, Any] | None:
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict):
        return None
    job = jobs.get(name)
    return job if isinstance(job, dict) else None


def _matching_commands(job: dict[str, Any]) -> list[str]:
    """Return every allowed command an existing step's `run:` line matches exactly."""
    matches: list[str] = []
    for step in job.get("steps") or []:
        if not isinstance(step, dict):
            continue
        run = step.get("run")
        if not isinstance(run, str):
            continue
        match = _RUN_PATTERN.fullmatch(run.strip())
        if match:
            matches.append(match.group(1))
    return matches


def discover_wired_command() -> str | None:
    """Return the one allowed command the gate job runs, or None if it is not exactly one."""
    workflow = _load_workflow()
    job = _job(workflow, JOB_NAME)
    if job is None:
        return None
    matches = _matching_commands(job)
    if len(matches) != 1:
        return None
    return matches[0]


def static_findings() -> list[str]:
    """Return every reason the wired job is not yet a real, singular reliability check."""
    if not WORKFLOW_PATH.is_file():
        return [f"{WORKFLOW_PATH.relative_to(TASK_ROOT)} does not exist"]
    workflow = _load_workflow()
    failures: list[str] = []

    job = _job(workflow, JOB_NAME)
    if job is None:
        return [f"{JOB_NAME!r} job is missing from {WORKFLOW_PATH.name}"]

    trigger = workflow.get("on", workflow.get(True))
    if not isinstance(trigger, dict) or "pull_request" not in trigger:
        failures.append("the workflow does not trigger on pull_request")

    verify_job = _job(workflow, COMPARISON_JOB_NAME)
    if verify_job is None:
        failures.append(f"{COMPARISON_JOB_NAME!r} job is missing from {WORKFLOW_PATH.name}")
    elif job.get("if") != verify_job.get("if"):
        failures.append(
            f"{JOB_NAME!r} job's export-branch exclusion does not match {COMPARISON_JOB_NAME!r}'s"
        )

    steps = job.get("steps") or []
    run_lines: list[str] = [
        run
        for step in steps
        if isinstance(step, dict) and isinstance((run := step.get("run")), str)
    ]
    if any(PLACEHOLDER_MARKER in line for line in run_lines):
        failures.append(f"{JOB_NAME!r} job still runs its supplied placeholder step")

    matches = _matching_commands(job)
    if len(matches) == 0:
        failures.append(
            f"{JOB_NAME!r} job's replacement step must run exactly `poe queue-contract` or "
            "`poe slo-contract` (found no step matching either)"
        )
    elif len(matches) > 1:
        failures.append(
            f"{JOB_NAME!r} job must run exactly one of `poe queue-contract`/`poe slo-contract`, "
            f"not both or more than one ({matches!r})"
        )

    return failures


def _uv_binary() -> Path:
    uv = TASK_ROOT / ".tools/bin/uv"
    if not uv.exists():
        uv = uv.with_suffix(".exe")
    return uv


def _run_poe(command: str) -> tuple[int, str]:
    """Run one `poe` target through the pinned uv binary, exactly like the CI job would.

    The nested run's queue-forcing timing lines are relayed to this session's own
    summary, so each forcing still reaches the job log exactly once, and are left out
    of the returned output that a failure message quotes.
    """
    from tests.failure import forcing_timing

    result = subprocess.run(
        [str(_uv_binary()), "run", "--frozen", "poe", command],
        cwd=TASK_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    output = result.stdout + result.stderr
    forcing_timing.relay(output)
    return result.returncode, forcing_timing.without_timing_lines(output)


def _sqs_client() -> Any:
    from tests.failure.queue_client import client

    return client()


def _read_redrive_policy(sqs: Any, url: str) -> dict[str, Any]:
    attributes = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["RedrivePolicy"])[
        "Attributes"
    ]
    return dict(json.loads(attributes["RedrivePolicy"]))


def _write_max_receive_count(sqs: Any, url: str, policy: dict[str, Any], value: int) -> None:
    updated = dict(policy)
    updated["maxReceiveCount"] = value
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"RedrivePolicy": json.dumps(updated)})


def _prove_queue_contract_rejects_broken_value() -> None:
    """Revert the deployed queue's own redrive policy, not any file, and confirm rejection.

    ``COLDLINE_QUEUE_MAX_RECEIVE_COUNT`` only ever reaches the queue through
    ``ensure_queue``'s idempotent ``set_queue_attributes`` call at container start; reading
    and writing that same attribute directly here reverts and restores the *effective*
    setting without touching ``compose.yaml`` or recreating any container, and leaves no file
    for the working-tree check to catch.
    """
    from tests.failure.queue_client import queue_url

    sqs = _sqs_client()
    url = queue_url(sqs, name=PRODUCTION_QUEUE_NAME)
    original = _read_redrive_policy(sqs, url)
    try:
        _write_max_receive_count(sqs, url, original, BROKEN_MAX_RECEIVE_COUNT)
        deployed = _read_redrive_policy(sqs, url)
        if int(deployed["maxReceiveCount"]) != BROKEN_MAX_RECEIVE_COUNT:
            raise AssertionError(
                "reverting the production queue's maxReceiveCount did not take effect; "
                f"expected {BROKEN_MAX_RECEIVE_COUNT}, read back {deployed['maxReceiveCount']}"
            )
        code, output = _run_poe("queue-contract")
        if code == 0:
            raise AssertionError(
                "poe queue-contract still passed with maxReceiveCount reverted to "
                f"{BROKEN_MAX_RECEIVE_COUNT} (Task 3.3's own known starting-broken value); "
                "the wired check does not actually depend on the redrive budget"
            )
    finally:
        _write_max_receive_count(sqs, url, original, int(original["maxReceiveCount"]))
        restored = _read_redrive_policy(sqs, url)
        if restored != original:
            raise AssertionError(
                "failed to restore the production queue's redrive policy to its original value"
            )


def _reload_alerts() -> None:
    result = subprocess.run(
        [str(_uv_binary()), "run", "--frozen", "poe", "reload-alerts"],
        cwd=TASK_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(f"poe reload-alerts failed:\n{result.stdout}{result.stderr}")


def _prove_slo_contract_rejects_broken_value() -> None:
    """Revert `infra/observability/alerts.yml`'s `for` on disk, and restore it byte-for-byte.

    Prometheus has no live API to change a rule's `for` duration; the file is the only
    control surface, and it only takes effect on reload (`poe reload-alerts`), exactly as
    Task 3.4's own contract documents.
    """
    original_bytes = ALERTS_PATH.read_bytes()
    original_text = original_bytes.decode("utf-8")
    match = re.search(r"(for:\s*)(\S+)", original_text)
    if match is None:
        raise AssertionError(f"{ALERTS_PATH} does not declare a `for:` duration to revert")
    broken_text = original_text[: match.start(2)] + BROKEN_ALERT_FOR + original_text[match.end(2) :]
    try:
        ALERTS_PATH.write_text(broken_text, encoding="utf-8")
        _reload_alerts()
        code, output = _run_poe("slo-contract")
        if code == 0:
            raise AssertionError(
                f"poe slo-contract still passed with `for` reverted to {BROKEN_ALERT_FOR} "
                "(Task 3.4's own known starting-broken value); the wired check does not "
                "actually depend on the alert window"
            )
    finally:
        ALERTS_PATH.write_bytes(original_bytes)
        _reload_alerts()
        if ALERTS_PATH.read_bytes() != original_bytes:
            raise AssertionError(f"failed to restore {ALERTS_PATH} to its original bytes")


def prove_gate_rejects_broken_value() -> None:
    """Run the wired command against the correct state, then against the broken one.

    Raises ``AssertionError`` naming exactly what went wrong: no recognized command wired, the
    command failing even at the correct configuration, the command not actually rejecting the
    broken configuration, or a failed restoration.
    """
    command = discover_wired_command()
    if command is None:
        raise AssertionError(
            f"{JOB_NAME!r} job's replacement step does not run exactly `poe queue-contract` "
            "or `poe slo-contract`; nothing to prove"
        )
    code, output = _run_poe(command)
    if code != 0:
        raise AssertionError(
            f"poe {command} does not even pass against the current, correctly configured "
            f"stack:\n{output}"
        )
    if command == "queue-contract":
        _prove_queue_contract_rejects_broken_value()
    else:
        _prove_slo_contract_rejects_broken_value()


if __name__ == "__main__":
    findings = static_findings()
    if findings:
        print("Static findings:", file=sys.stderr)
        for finding in findings:
            print(f"- {finding}", file=sys.stderr)
        sys.exit(1)
    prove_gate_rejects_broken_value()
    print("Reliability gate verification passed: the wired check is real and actually gates.")
