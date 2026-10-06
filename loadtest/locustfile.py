"""Coldline.

===================

File:              loadtest/locustfile.py
Component:         Load test — Locust user
Purpose:           Generate the pinned traffic profile against the Coldline API.
Interacts With:    The running Coldline API
Sprint/Task:       Sprint 1 — Project 1
Concepts:          Controlled load experiments
Tools:             Python 3.12, Locust
"""

import uuid
from datetime import UTC, datetime

from locust import HttpUser, between, task

# Pinned traffic shape for both baseline runs and the latency-injected run — never change
# these values between runs, or the comparison in Step 1 of the lesson is invalid.
#
# Retuned for Task 1.5: the single sequential worker's
# real capacity is ~4 jobs/sec (250 ms/job). The original Task 1.4 profile (20 users,
# 0.05-0.15s wait) generates ~100-120 req/s of arrival traffic — a ~25x mismatch that drives
# the Redis Streams queue into runaway, ever-growing backlog within the first second or two.
# That backlog collapse means "worker task duration" (accepted-to-terminal) only ever measures
# queue-wait time, never real per-job service time. These values are picked so sustained
# arrival lands meaningfully under the worker's ~4 jobs/sec capacity, producing light, honest
# queueing instead of catastrophic backlog collapse.
WAIT_TIME_MIN_SECONDS = 1.0
WAIT_TIME_MAX_SECONDS = 1.4


class ColdlineUser(HttpUser):
    """Send synthetic out-of-range temperature readings at a pinned rate."""

    wait_time = between(WAIT_TIME_MIN_SECONDS, WAIT_TIME_MAX_SECONDS)

    @task
    def submit_exception_reading(self) -> None:
        """Submit an out-of-range temperature reading to the API."""
        self.client.post(
            "/api/v1/readings",
            json={
                "reading_id": f"load-{uuid.uuid4().hex}",
                "shipment_id": f"load-shipment-{uuid.uuid4().hex}",
                "temperature_c": 25.0,
                "allowed_min_c": 0.0,
                "allowed_max_c": 10.0,
                "recorded_at": datetime.now(UTC).isoformat(),
            },
        )
