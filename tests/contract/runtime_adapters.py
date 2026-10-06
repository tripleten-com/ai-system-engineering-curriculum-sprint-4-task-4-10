"""Coldline.

===================

File:              tests/contract/runtime_adapters.py
Component:         Contract tests — Runtime Adapters
Purpose:           Exercise PostgreSQL and SQS adapter behavior against the running stack.
Interacts With:    Published interfaces and repository boundaries
Sprint/Task:       Sprint 4 — Project 4
Concepts:          Compatibility, ownership, export safety, dead-letter redrive, raw handling note
Tools:             Python 3.12, pytest, PostgreSQL, boto3, LocalStack
"""

import asyncio
import time
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import asyncpg

from adapters.persistence import PostgresExceptionRepository
from adapters.queue import SqsJobQueue, create_sqs_client, ensure_queue
from common.audit import AuditRecord, AuditSink
from domain.contracts import (
    ExceptionJob,
    ExceptionRecord,
    ExceptionState,
    JobDelivery,
    ModelAnswer,
    ModelRequest,
    SensorReading,
)
from worker.procedures import ProcedureExcerpt
from worker.use_cases import ProcessingDisposition, WorkerApplication

DATABASE_URL = "postgresql://coldline:coldline_local@postgres:5432/coldline"
LOCALSTACK_ENDPOINT = "http://localstack:4566"
# Margin added to a queue's own visibility timeout while waiting for a first receive.
FIRST_RECEIVE_MARGIN_SECONDS = 10.0
HANDLING_NOTE = "verify: the raw note is kept as written, +1 555 0199 included"


class AlwaysFailProvider:
    """Fail deterministically at the active model-provider boundary."""

    async def summarize(self, request: ModelRequest) -> ModelAnswer:
        """Raise the fixed integration failure."""
        raise TimeoutError("integration provider failure")


class NoProcedure:
    """Answer every lookup with an empty excerpt, so no retrieval runs here."""

    async def find(self, reading: SensorReading) -> ProcedureExcerpt:
        """Return the empty excerpt."""
        return ProcedureExcerpt(document_id=None, chunk_id=None, text="", window_minutes=None)


class _DiscardAuditStore:
    """Keep audit records in memory for this queue verifier.

    It runs inside the worker image, which has no ``tests`` package, and it checks
    the queue, not the audit trail.
    """

    def __init__(self) -> None:
        self._records: list[AuditRecord] = []

    async def append(self, record: AuditRecord) -> AuditRecord:
        self._records.append(record)
        return record

    async def trail(self, exception_id: str) -> list[AuditRecord]:
        return [record for record in self._records if record.exception_id == exception_id]


async def verify() -> None:
    """Verify initialization, durable identity, the note column, and dead-letter recovery."""
    identity = uuid4().hex
    exception_id = f"verify-{identity}"
    queue_name = f"coldline-verify-{identity}"
    dead_letter_name = f"{queue_name}-dlq"
    now = datetime.now(UTC)
    reading = SensorReading(
        reading_id=f"reading-{identity}",
        shipment_id="shipment-integration",
        temperature_c=9.2,
        allowed_min_c=2.0,
        allowed_max_c=8.0,
        recorded_at=now,
        handling_note=HANDLING_NOTE,
    )
    record = ExceptionRecord(
        exception_id=exception_id,
        reading=reading,
        state=ExceptionState.RECEIVED,
        accepted_at=now,
        updated_at=now,
    )
    pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=2)
    sqs = create_sqs_client(
        endpoint_url=LOCALSTACK_ENDPOINT,
        region_name="us-east-1",
        access_key_id="localstack-development-key",
        secret_access_key="localstack-development-secret",
    )
    try:
        assert await pool.fetchval("SELECT to_regclass('public.exceptions')") == "exceptions"

        repository = PostgresExceptionRepository(pool)
        created = await repository.create(record)
        duplicate = await repository.create(record)
        assert created == duplicate
        assert created.reading.handling_note == HANDLING_NOTE
        # The Project 4 opening migration's column holds the raw note beside
        # the JSON reading; the initializer brought the schema to head.
        stored_note = await pool.fetchval(
            "SELECT handling_note FROM exceptions WHERE exception_id = $1", exception_id
        )
        assert stored_note == HANDLING_NOTE, stored_note
        queued = await repository.transition(
            exception_id, {ExceptionState.RECEIVED}, ExceptionState.QUEUED
        )
        assert queued.state is ExceptionState.QUEUED

        queue_url, dlq_url = await asyncio.to_thread(
            ensure_queue,
            sqs,
            queue_name=queue_name,
            dead_letter_name=dead_letter_name,
            visibility_timeout_seconds=1,
            max_receive_count=2,
        )
        queue = SqsJobQueue(sqs, queue_url=queue_url, wait_time_seconds=1)
        job = ExceptionJob(exception_id=exception_id, reading=reading, accepted_at=now)
        await queue.publish(job)
        first = await queue.read(block_ms=2000)
        assert first is not None and first.job == job
        assert first.job.reading.handling_note == HANDLING_NOTE
        assert first.delivery_count == 1
        assert await queue.pending_count() == 1

        # A message the first receiver never acknowledges becomes visible to any
        # receiver again once the queue's own visibility timeout elapses; SQS
        # counts that as the *same* message's second delivery, not a duplicate.
        # LocalStack's own revisibility latency runs measurably past the
        # configured 1 s timeout, so this polls rather than sleeping once and
        # checking a single time.
        second = await _poll_for_redelivery(queue, job)
        assert second is not None and second.job == job
        assert second.delivery_count == 2
        await queue.acknowledge(second.message_id)
        assert await queue.pending_count() == 0

        # One delivery beyond the bound moves the message to the dead-letter
        # queue automatically; nothing here acknowledges it, so this proves the
        # *queue's own* redrive policy, not application-level handling of it.
        await queue.publish(job)
        for _ in range(3):
            delivery = await queue.read(block_ms=2000)
            if delivery is None:
                break
            await asyncio.sleep(1.2)
        dlq_depth = await asyncio.to_thread(
            lambda: int(
                sqs.get_queue_attributes(
                    QueueUrl=dlq_url, AttributeNames=["ApproximateNumberOfMessages"]
                )["Attributes"]["ApproximateNumberOfMessages"]
            )
        )
        assert dlq_depth >= 1

        terminal = await WorkerApplication(
            repository,
            AlwaysFailProvider(),
            NoProcedure(),
            audit=AuditSink(_DiscardAuditStore()),
            clock=lambda: now,
            maximum_attempts=3,
        ).process(job, delivery_count=3)
        failed = await repository.get(exception_id)
        assert terminal is ProcessingDisposition.ACK
        assert failed is not None and failed.state is ExceptionState.FAILED
        assert failed.failure_reason == "model_provider_exhausted"

        # The *configured production queue* — not this test's own throwaway
        # queue — must give a delivery at least one retry before redrive: a
        # worker that crashes once, never acknowledging what it received,
        # must still get the job back rather than lose it to the dead-letter
        # queue on the very next receive. This is what makes
        # queue_max_receive_count=1 a wrong configuration even though it is
        # within the published Field bounds.
        production_url = await asyncio.to_thread(
            lambda: sqs.get_queue_url(QueueName="coldline-exception-jobs")["QueueUrl"]
        )
        production_queue = SqsJobQueue(sqs, queue_url=production_url, wait_time_seconds=1)
        recovery_job = ExceptionJob(
            exception_id=f"recovery-{identity}", reading=reading, accepted_at=now
        )
        await production_queue.publish(recovery_job)
        try:
            messages, first_receive_seconds, deadline_seconds = await _receive_first(
                sqs, production_url
            )
            # One timing line per forcing; see _forcing_line.
            print(
                _forcing_line(
                    first_receive_seconds=first_receive_seconds,
                    receives_observed=len(messages),
                    deadline_seconds=deadline_seconds,
                ),
                flush=True,
            )
            assert messages, (
                "the first receive did not observe the just-published message within one "
                "visibility timeout; production queue counts: "
                f"{await asyncio.to_thread(_queue_counts, sqs, production_url)}"
            )
            # A per-call VisibilityTimeout on receive_message is not reliably honored by
            # this LocalStack version; change_message_visibility on the message already
            # in hand is the documented, dependable way to force it visible again
            # without waiting out the production queue's real (much longer) timeout.
            await asyncio.to_thread(
                sqs.change_message_visibility,
                QueueUrl=production_url,
                ReceiptHandle=messages[0]["ReceiptHandle"],
                VisibilityTimeout=0,
            )
            # Rare path: if a killed receiver's open poll took this message first, that dead
            # receive already used one delivery, so even maxReceiveCount=2 can fail here.
            recovered = await _poll_for_redelivery(production_queue, recovery_job)
            assert (
                recovered is not None
                and recovered.job == recovery_job
                and recovered.delivery_count >= 2
            ), (
                "one unacknowledged delivery must not exhaust the configured redrive "
                "budget; queue_max_receive_count must allow at least one retry"
            )
            await production_queue.acknowledge(recovered.message_id)
        finally:
            await asyncio.to_thread(_purge_queue_quietly, sqs, "coldline-exception-jobs")
            await asyncio.to_thread(_purge_queue_quietly, sqs, "coldline-exception-jobs-dlq")
    finally:
        await asyncio.to_thread(_delete_queue_quietly, sqs, queue_name)
        await asyncio.to_thread(_delete_queue_quietly, sqs, dead_letter_name)
        await pool.execute("DELETE FROM exceptions WHERE exception_id = $1", exception_id)
        await pool.close()
    print(
        "Integration verification passed: PostgreSQL, SQS dead-letter recovery, and terminal "
        "failure contracts are valid."
    )


async def _poll_for_redelivery(
    queue: SqsJobQueue, expected: ExceptionJob, *, attempts: int = 20, delay_seconds: float = 0.5
) -> JobDelivery | None:
    """Wait for a message to become visible again, tolerating variable transport latency.

    LocalStack's own revisibility latency for a short visibility timeout has been observed
    to run measurably past the configured bound. A single sleep-then-check assumes an exact
    latency; repeatedly checking with a short pause between attempts absorbs the variance
    instead, up to a generous total budget (``attempts * delay_seconds`` seconds).
    """
    for _ in range(attempts):
        delivery = await queue.claim_stale(minimum_idle_ms=0)
        if delivery is not None and delivery.job == expected:
            return delivery
        await asyncio.sleep(delay_seconds)
    return None


async def _receive_first(sqs: Any, url: str) -> tuple[list[dict[str, Any]], float, float]:
    """Receive the just-published message, polling past an empty first answer.

    A worker container killed during its own long poll leaves that request
    open inside LocalStack, which can hand the next published message to it.
    The message then stays invisible for one visibility timeout. Polling until
    the queue's own visibility timeout plus a margin has passed absorbs that
    instead of failing on the first empty receive.

    Returns the messages, the seconds the receive took, and the deadline it had.
    """
    visibility_timeout = await asyncio.to_thread(
        lambda: int(
            sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["VisibilityTimeout"])[
                "Attributes"
            ]["VisibilityTimeout"]
        )
    )
    deadline_seconds = visibility_timeout + FIRST_RECEIVE_MARGIN_SECONDS
    started = time.monotonic()
    while True:
        response = await asyncio.to_thread(
            sqs.receive_message,
            QueueUrl=url,
            MaxNumberOfMessages=1,
            WaitTimeSeconds=2,
        )
        messages: list[dict[str, Any]] = response.get("Messages") or []
        elapsed = time.monotonic() - started
        if messages or elapsed >= deadline_seconds:
            return messages, elapsed, deadline_seconds


def _forcing_line(
    *, first_receive_seconds: float, receives_observed: int, deadline_seconds: float
) -> str:
    """Return this forcing's timing line in the fixed shared queue-forcing format.

    The same format as ``tests/failure/forcing_timing.py``, spelled out here because
    this verifier is piped into a container and cannot import ``tests``;
    ``tests/contract/test_runtime_adapters.py`` relays the line from the container's
    output. A first receive that never saw the message reports the time it waited,
    which is at least the deadline, and ``not_dead_lettered`` as its outcome.
    """
    outcome = "received" if receives_observed else "not_dead_lettered"
    return (
        f"queue-forcing helper=runtime_adapters first_receive_seconds={first_receive_seconds:.1f}"
        f" receives_observed={receives_observed} deadline_seconds={deadline_seconds:.1f}"
        f" outcome={outcome}"
    )


def _queue_counts(sqs: Any, url: str) -> dict[str, int]:
    """Return one queue's visible and in-flight message counts, for a failure message."""
    attributes = sqs.get_queue_attributes(
        QueueUrl=url,
        AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )["Attributes"]
    return {
        "approximate_number_of_messages": int(attributes["ApproximateNumberOfMessages"]),
        "approximate_number_of_messages_not_visible": int(
            attributes["ApproximateNumberOfMessagesNotVisible"]
        ),
    }


def _delete_queue_quietly(sqs: object, name: str) -> None:
    """Remove one exercise queue, tolerating a name that was never created."""
    try:
        url = sqs.get_queue_url(QueueName=name)["QueueUrl"]  # type: ignore[attr-defined]
        sqs.delete_queue(QueueUrl=url)  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 - best-effort cleanup, never the test's own failure
        pass


def _purge_queue_quietly(sqs: object, name: str) -> None:
    """Empty one *shared, provisioned* queue without deleting it."""
    try:
        url = sqs.get_queue_url(QueueName=name)["QueueUrl"]  # type: ignore[attr-defined]
        sqs.purge_queue(QueueUrl=url)  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 - best-effort cleanup, never the test's own failure
        pass


if __name__ == "__main__":
    asyncio.run(verify())
