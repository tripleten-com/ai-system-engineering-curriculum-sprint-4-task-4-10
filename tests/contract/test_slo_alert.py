"""Coldline.

===================

File:              tests/contract/test_slo_alert.py
Component:         Contract tests — SLO alert
Purpose:           Prove the deployed alert rule is bounded, fires, and resolves.
Interacts With:    Docker Compose, Prometheus, Alertmanager, LocalStack SQS, and the API
Sprint/Task:       Sprint 3 — Project 3
Concepts:          SLO/alert, dead-letter redrive, deterministic infrastructure
Tools:             Python 3.12, pytest, httpx, Docker Compose
"""

import subprocess
from pathlib import Path

import pytest

from tests.contract import slo_alert

TASK_ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.runtime


def _compose(*arguments: str) -> None:
    """Run one Docker Compose command against this Task's stack."""
    subprocess.run(["docker", "compose", *arguments], cwd=TASK_ROOT, check=True)


def test_alert_threshold_is_actionable_and_recovers() -> None:
    """Catch a `for` value that is legal but too long to ever fire in the exercise.

    The worker container is stopped for the forcing step, exactly like the
    supplied `poe worker-stop`/`poe trigger-alert-load` exercise, and always
    restarted afterward. `tests/failure/trigger_alert_load.py` itself restarts
    the worker once the message is dead-lettered, so this only has to stop it
    first and guarantee it ends up running again.
    """
    bound = slo_alert.read_deployed_for_seconds()
    assert slo_alert.FOR_LOWER_BOUND_SECONDS <= bound <= slo_alert.FOR_UPPER_BOUND_SECONDS, (
        f"{slo_alert.RULE_NAME}'s for={bound}s is outside the published "
        f"[{slo_alert.FOR_LOWER_BOUND_SECONDS}, {slo_alert.FOR_UPPER_BOUND_SECONDS}]s bound"
    )

    _compose("stop", "worker")
    try:
        exit_code, evidence = slo_alert.verify()
    finally:
        _compose("start", "worker")

    assert exit_code == 0, evidence
