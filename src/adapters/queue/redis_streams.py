"""Coldline.

===================

File:              src/adapters/queue/redis_streams.py
Component:         Adapter — Redis Streams
Purpose:           Implement the supplied Redis Streams JobQueue adapter.
Interacts With:    Domain contracts, ports, and local providers
Sprint/Task:       Sprint 1 — Project 1
Concepts:          Boundary translation, deterministic infrastructure
Tools:             Python 3.12, Redis, OpenTelemetry
"""

from typing import cast

from opentelemetry import trace
from opentelemetry.propagate import inject
from redis.asyncio import Redis
from redis.exceptions import ResponseError

from domain.contracts import ExceptionJob, JobDelivery

_TRACER = trace.get_tracer(__name__)
_CARRIER_KEYS = ("traceparent", "tracestate")


def _extract_carrier(fields: dict[object, object]) -> dict[str, str]:
    """Pull W3C trace-context headers out of a decoded Redis Streams message."""
    carrier: dict[str, str] = {}
    for key in _CARRIER_KEYS:
        try:
            value = _field(fields, key)
        except KeyError:
            continue
        carrier[key] = _text(value)
    return carrier


def encode_job(job: ExceptionJob) -> str:
    """Serialize one canonical job for Redis storage."""
    return job.model_dump_json()


def decode_job(payload: str | bytes) -> ExceptionJob:
    """Deserialize one canonical job from Redis storage."""
    return ExceptionJob.model_validate_json(payload)


class RedisJobQueue:
    """Translate the provider-neutral ``JobQueue`` contract to Redis Streams.

    One stream carries the jobs. One consumer group tracks ownership and pending
    deliveries. The worker can claim an idle pending message after the configured
    recovery window, so a process restart does not discard accepted work.
    """

    def __init__(
        self,
        client: Redis,
        *,
        stream: str,
        group: str,
        consumer: str,
    ) -> None:
        """Bind the adapter to one protected stream, group, and consumer identity."""
        self._client = client
        self._stream = stream
        self._group = group
        self._consumer = consumer

    async def initialize(self) -> None:
        """Create the stream and consumer group idempotently."""
        try:
            await self._client.xgroup_create(
                name=self._stream,
                groupname=self._group,
                id="0-0",
                mkstream=True,
            )
        except ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    async def publish(self, job: ExceptionJob) -> str:
        """Publish one job, carrying trace context across the queue boundary."""
        with _TRACER.start_as_current_span(
            "job_queue.publish",
            attributes={"coldline.exception_id": job.exception_id},
        ):
            carrier: dict[str, str] = {}
            inject(carrier)
            fields = {"job": encode_job(job), **carrier}
            # mypy: `fields` is dict[str, str], but xadd's fields param is invariantly
            # typed as Dict[<str-or-bytes-or-numeric union>, ...]; the runtime values are
            # always plain strings, which redis-py accepts.
            message_id = await self._client.xadd(self._stream, fields)  # type: ignore[arg-type]
        return _text(message_id)

    async def read(self, *, block_ms: int = 1000) -> JobDelivery | None:
        """Read at most one new group delivery within the bounded wait.

        Redis keeps the returned message in the pending list until the worker
        explicitly acknowledges it after durable terminal persistence.
        """
        result = await self._client.xreadgroup(
            groupname=self._group,
            consumername=self._consumer,
            streams={self._stream: ">"},
            count=1,
            block=block_ms,
        )
        if not result:
            return None
        _, messages = result[0]
        message_id, fields = messages[0]
        return JobDelivery(
            message_id=_text(message_id),
            job=decode_job(_field(fields, "job")),
            delivery_count=1,
            trace_carrier=_extract_carrier(fields),
        )

    async def claim_stale(self, *, minimum_idle_ms: int) -> JobDelivery | None:
        """Take ownership of one idle pending message for restart recovery.

        The returned delivery count comes from Redis, not local memory. The use
        case uses that durable count to enforce the three-attempt limit.
        """
        result = await self._client.xautoclaim(
            name=self._stream,
            groupname=self._group,
            consumername=self._consumer,
            min_idle_time=minimum_idle_ms,
            start_id="0-0",
            count=1,
        )
        messages = result[1]
        if not messages:
            return None
        message_id, fields = messages[0]
        pending = await self._client.xpending_range(
            self._stream,
            self._group,
            min=message_id,
            max=message_id,
            count=1,
        )
        delivery_count = int(pending[0]["times_delivered"]) if pending else 1
        return JobDelivery(
            message_id=_text(message_id),
            job=decode_job(_field(fields, "job")),
            delivery_count=delivery_count,
            trace_carrier=_extract_carrier(fields),
        )

    async def acknowledge(self, message_id: str) -> None:
        """Remove one message from the pending list after safe persistence.

        Callers own the ordering rule. This adapter exposes the operation but
        never acknowledges automatically after a read or claim.
        """
        await self._client.xack(self._stream, self._group, message_id)

    async def queue_depth(self) -> int:
        """Return the current stream length for diagnostic evidence."""
        return int(await self._client.xlen(self._stream))

    async def pending_count(self) -> int:
        """Return the consumer group's pending-message count."""
        summary = await self._client.xpending(self._stream, self._group)
        return int(summary["pending"])


def _text(value: str | bytes) -> str:
    """Normalize Redis response text."""
    return value.decode("utf-8") if isinstance(value, bytes) else value


def _field(fields: dict[object, object], name: str) -> str | bytes:
    """Read one field from decoded or byte-oriented Redis responses."""
    if name in fields:
        return cast(str | bytes, fields[name])
    return cast(str | bytes, fields[name.encode("utf-8")])
