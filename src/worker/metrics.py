"""Coldline.

===================

File:              src/worker/metrics.py
Component:         Worker — Metrics
Purpose:           Define bounded Prometheus metrics for exception processing.
Interacts With:    JobQueue, domain, ports, and adapters
Sprint/Task:       Sprint 3 — Project 3
Concepts:          Background processing, retries, idempotency, dead-letter redrive, SLO/alert
Tools:             Python 3.12, Prometheus
"""

from datetime import datetime

from prometheus_client import Counter, Gauge, Histogram

JOBS = Counter(
    "coldline_exception_jobs_total",
    "Count terminal exception jobs.",
)
QUEUE_DEPTH = Gauge(
    "coldline_job_queue_stream_length",
    "Report the current queue depth (messages available to receive).",
)
QUEUE_PENDING = Gauge(
    "coldline_job_queue_pending_messages",
    "Report the current in-flight message count (received but not yet acknowledged).",
)
# Task 3.4's one SLO signal: the dead-letter queue's own depth. A sustained
# non-zero reading means at least one exception has been dead-lettered and not
# yet redriven — a user-visible loss of processing, not infrastructure noise.
DEAD_LETTER_DEPTH = Gauge(
    "coldline_job_queue_dead_letter_depth",
    "Report the current dead-letter queue depth.",
)
PROCESSING_DURATION = Histogram(
    "coldline_exception_processing_duration_seconds",
    "Measure accepted-to-terminal exception duration.",
    buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
)


def observe_processing_duration(
    accepted_at: datetime,
    completed_at: datetime,
) -> None:
    """Record the supplied opening-checkpoint processing observation."""
    elapsed = max(0.0, (completed_at - accepted_at).total_seconds())
    PROCESSING_DURATION.observe(elapsed)
