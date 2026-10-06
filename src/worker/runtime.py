"""Coldline.

===================

File:              src/worker/runtime.py
Component:         Worker — Runtime
Purpose:           Run the provider-neutral worker loop after composition is complete.
Interacts With:    Redis Streams, domain, ports, and adapters
Sprint/Task:       Sprint 1 — Project 1
Concepts:          Background processing, retries, idempotency
Tools:             Python 3.12, OpenTelemetry
"""

import asyncio
import logging
from datetime import UTC, datetime

from opentelemetry import trace
from opentelemetry.propagate import extract

from domain.contracts import JobDelivery
from ports import JobQueue
from worker.metrics import JOBS, QUEUE_DEPTH, QUEUE_PENDING, observe_processing_duration
from worker.use_cases import ProcessingDisposition, WorkerApplication

LOGGER = logging.getLogger(__name__)


async def run_loop(
    queue: JobQueue,
    application: WorkerApplication,
    tracer: trace.Tracer,
    *,
    stale_message_ms: int,
    transport_error_backoff_seconds: float = 1.0,
) -> None:
    """Consume recoverable pending work before waiting for new jobs.

    Every loop first checks for a message left pending by an interrupted worker.
    Unexpected delivery errors are logged and left pending, allowing the bounded
    recovery path to retry them instead of losing the job.
    """
    while True:
        try:
            delivery = await queue.claim_stale(minimum_idle_ms=stale_message_ms)
            if delivery is None:
                delivery = await queue.read(block_ms=1000)
            await _update_queue_metrics(queue)
        except Exception:
            LOGGER.exception("queue operation failed; retrying the worker loop")
            await asyncio.sleep(transport_error_backoff_seconds)
            continue
        if delivery is not None:
            try:
                await _process_delivery(delivery, queue, application, tracer)
            except Exception:
                LOGGER.exception(
                    "delivery failed exception_id=%s message_id=%s; leaving it pending",
                    delivery.job.exception_id,
                    delivery.message_id,
                )


async def _process_delivery(
    delivery: JobDelivery,
    queue: JobQueue,
    application: WorkerApplication,
    tracer: trace.Tracer,
) -> None:
    """Run one use-case attempt and acknowledge only a safe disposition.

    ``RETRY`` leaves the message pending. Both acknowledgement dispositions mean
    that durable state already makes another side effect unnecessary.
    """
    attributes: dict[str, str | int] = {
        "coldline.exception_id": delivery.job.exception_id,
        "coldline.message_id": delivery.message_id,
        "coldline.delivery_count": delivery.delivery_count,
    }
    parent_context = extract(delivery.trace_carrier)
    with tracer.start_as_current_span(
        "coldline.process_exception",
        context=parent_context,
        attributes=attributes,
    ):
        disposition = await application.process(
            delivery.job,
            delivery_count=delivery.delivery_count,
        )
        if disposition in {
            ProcessingDisposition.ACK,
            ProcessingDisposition.ACK_EXISTING,
            ProcessingDisposition.ACK_MISSING,
        }:
            await queue.acknowledge(delivery.message_id)
        if disposition is ProcessingDisposition.ACK_MISSING:
            LOGGER.warning(
                "acknowledging orphaned job exception_id=%s message_id=%s",
                delivery.job.exception_id,
                delivery.message_id,
            )
        if disposition is ProcessingDisposition.ACK:
            completed_at = datetime.now(UTC)
            JOBS.inc()
            observe_processing_duration(delivery.job.accepted_at, completed_at)
        LOGGER.info(
            "processed exception_id=%s disposition=%s",
            delivery.job.exception_id,
            disposition.value,
        )


async def _update_queue_metrics(queue: JobQueue) -> None:
    """Refresh bounded queue diagnostic signals."""
    QUEUE_DEPTH.set(await queue.queue_depth())
    QUEUE_PENDING.set(await queue.pending_count())
