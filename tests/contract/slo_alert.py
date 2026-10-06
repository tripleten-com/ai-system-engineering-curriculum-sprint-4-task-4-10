"""Coldline.

===================

File:              tests/contract/slo_alert.py
Component:         Contract tests — SLO alert
Purpose:           Exercise the deployed alert rule's bound, firing, and resolution.
Interacts With:    Prometheus, Alertmanager, the supplied failure-exercise scripts
Sprint/Task:       Sprint 3 — Project 3
Concepts:          SLO/alert, dead-letter redrive, compatibility, evidence
Tools:             Python 3.12, httpx

This module is a ``verify()``-style checker in the same spirit as
``tests/contract/runtime_adapters.py``, but it runs directly against this
host's published ports rather than inside a one-off ``docker compose run``
container. ``runtime_adapters.py`` needs the one-off container because its
own dependencies (PostgreSQL, the internal LocalStack hostname) are reachable
only from inside the Compose network. Every dependency this checker needs —
the API, Prometheus, Alertmanager, and LocalStack SQS — is already published
to a host port in ``compose.yaml``, exactly like
``tests/failure/force_dlq_arrival.py`` and ``tests/failure/queue_client.py``
already assume; running it directly on the host avoids a container that would
have to shell back out to Docker Compose mid-script to restart the worker.
"""

import httpx

from tests.runtime_config import host_port

FOR_LOWER_BOUND_SECONDS = 5.0
FOR_UPPER_BOUND_SECONDS = 120.0
RULE_GROUP = "coldline-recovery"
RULE_NAME = "ColdlineDeadLetterQueueBacklog"


def prometheus_base_url() -> str:
    """Return Prometheus's host-reachable base URL."""
    port = host_port("COLDLINE_PROMETHEUS_HOST_PORT", 9090)
    return f"http://localhost:{port}"


def read_deployed_for_seconds() -> float:
    """Read the alert rule's configured `for` duration back from Prometheus's own API.

    Reads the *deployed* rule through ``/api/v1/rules``, not the YAML file on
    disk, matching the established precedent of asking the running system
    rather than trusting the file — the same way
    ``tests/failure/force_dlq_arrival.py`` reads SQS's own ``RedrivePolicy``
    back rather than trusting `compose.yaml`.
    """
    with httpx.Client(base_url=prometheus_base_url(), timeout=5.0) as prometheus:
        response = prometheus.get("/api/v1/rules")
        response.raise_for_status()
    payload = response.json()
    for group in payload["data"]["groups"]:
        if group["name"] != RULE_GROUP:
            continue
        for rule in group["rules"]:
            if rule.get("name") == RULE_NAME:
                return float(rule["duration"])
    raise AssertionError(f"{RULE_NAME} is not a deployed Prometheus rule")


def verify() -> tuple[int, str]:
    """Force one exception to dead-letter, prove the alert fires, then prove it resolves.

    Delegates to the two supplied student exercise scripts
    (`tests/failure/trigger_alert_load.py`, `tests/failure/verify_alert_recovery.py`)
    so the automated check exercises exactly what a student runs by hand
    (`poe trigger-alert-load`, `poe verify-alert-recovery`), not a
    reimplementation that could drift from it.
    """
    from tests.failure import trigger_alert_load, verify_alert_recovery

    load_exit = trigger_alert_load.main()
    if load_exit != 0:
        return load_exit, "trigger_alert_load did not observe the alert become active"
    recovery_exit = verify_alert_recovery.main()
    if recovery_exit != 0:
        return recovery_exit, "verify_alert_recovery did not observe completion and resolution"
    return 0, "trigger_alert_load and verify_alert_recovery both passed"
