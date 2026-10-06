"""Coldline.

===================

File:              loadtest/model_provider_latency.py
Component:         Load test — Provider latency injection
Purpose:           The ONLY file you may edit for Task 1.4. Wire in the injected delay.
Interacts With:    The running worker's COLDLINE_MODEL_LATENCY_MS setting
Sprint/Task:       Sprint 1 — Project 1
Concepts:          Controlled experiments, one independent variable
Tools:             Python 3.12, Docker Compose
"""

import os
import subprocess

# The worker's baseline ModelProvider latency (matches WorkerSettings.model_latency_ms's
# default in src/worker/config.py). Do not change this — it must match the real baseline.
BASELINE_LATENCY_MS = 250

# Fork-base preparation (Task 1.5): Task 1.4's assignment is completed here so that Task
# 1.5's own lesson (capacity analysis) has a working, completed load-test harness to build on.
INJECTED_DELAY_MS = 300


def injected_latency_ms() -> int:
    """Return the ModelProvider latency (ms) to use for the latency-injected run."""
    return BASELINE_LATENCY_MS + INJECTED_DELAY_MS


def apply_latency_override(latency_ms: int) -> None:
    """Restart the worker with COLDLINE_MODEL_LATENCY_MS set to the given value.

    The worker only reads its settings once, at startup — changing the environment
    alone does nothing until the container restarts.
    """
    subprocess.run(
        ["docker", "compose", "--profile", "observability", "up", "-d", "--no-deps", "worker"],
        env={**os.environ, "COLDLINE_MODEL_LATENCY_MS": str(latency_ms)},
        check=True,
    )
