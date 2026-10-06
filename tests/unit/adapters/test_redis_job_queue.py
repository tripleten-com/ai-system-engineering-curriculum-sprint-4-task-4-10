"""Coldline.

===================

File:              tests/unit/adapters/test_redis_job_queue.py
Component:         Unit tests — Test Redis Job Queue
Purpose:           Unit tests for Redis Streams job serialization.
Interacts With:    One isolated source responsibility
Sprint/Task:       Sprint 1 — Project 1
Concepts:          Fast feedback, failure paths, state invariants
Tools:             Python 3.12, pytest
"""

from datetime import UTC, datetime

from adapters.queue import decode_job, encode_job
from domain.contracts import ExceptionJob, SensorReading


def test_job_round_trip_preserves_the_shared_contract() -> None:
    """Redis serialization must preserve the canonical exception job."""
    job = ExceptionJob(
        exception_id="exc-001",
        accepted_at=datetime(2026, 8, 28, tzinfo=UTC),
        reading=SensorReading(
            reading_id="reading-syn-001",
            shipment_id="shipment-syn-001",
            temperature_c=9.2,
            allowed_min_c=2.0,
            allowed_max_c=8.0,
            recorded_at=datetime(2026, 8, 28, tzinfo=UTC),
        ),
    )

    assert decode_job(encode_job(job)) == job
