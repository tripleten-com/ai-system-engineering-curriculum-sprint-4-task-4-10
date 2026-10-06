"""Coldline.

===================

File:              src/api/runtime.py
Component:         API — Runtime
Purpose:           Expose initialized runtime adapters through provider-neutral collaborators.
Interacts With:    FastAPI, domain, ports, adapters, the audit sink
Sprint/Task:       Sprint 4 — Project 4
Concepts:          HTTP boundary, composition, asynchronous work, dead-letter redrive, audit
Tools:             Python 3.12, PostgreSQL, LocalStack SQS, boto3
"""

import time
from collections.abc import Mapping

import asyncpg

from common.audit import AuditEvent, AuditRecord, AuditSink
from domain.contracts import (
    ExceptionJob,
    ExceptionRecord,
    ExceptionState,
    JobDelivery,
    RetrievalRequest,
    RetrievalResult,
)
from domain.idempotency import IdempotencyClaim, IdempotencyStore, StoredResponse
from domain.repositories import DocumentRepository, ExceptionRepository
from ports import JobQueue, ObjectStore, Retriever


class RuntimeBindings:
    """Bridge FastAPI construction with adapters created during lifespan startup.

    FastAPI needs the application object before its asynchronous lifespan runs.
    This small forwarding object receives PostgreSQL, queue, object-storage,
    retrieval, and audit adapters at startup and closes them through the
    composition root at shutdown.
    """

    def __init__(self) -> None:
        """Create an uninitialized binding set."""
        self.pool: asyncpg.Pool | None = None
        self.repository: ExceptionRepository | None = None
        self.queue: JobQueue | None = None
        self.object_store: ObjectStore | None = None
        self.retriever: Retriever | None = None
        self.document_repository: DocumentRepository | None = None
        self.idempotency_store: IdempotencyStore | None = None
        self.audit: AuditSink | None = None
        self.serving_since: float | None = None
        self.ready_delay_seconds: float = 0.0

    def mark_serving(self, ready_delay_seconds: float) -> None:
        """Start the warm-up clock the readiness probe consults."""
        self.serving_since = time.monotonic()
        self.ready_delay_seconds = ready_delay_seconds

    def warmed_up(self) -> bool:
        """Return true once the process has served for its configured warm-up."""
        if self.serving_since is None:
            return False
        return time.monotonic() - self.serving_since >= self.ready_delay_seconds

    def documents(self) -> DocumentRepository | None:
        """Resolve the composed document repository at call time.

        The repository is built during startup, after the HTTP application
        object exists, so the document service receives this provider rather
        than a value. ``None`` means the student factory has not returned an
        implementation yet.
        """
        return self.document_repository

    async def get(self, exception_id: str) -> ExceptionRecord | None:
        """Forward one repository read after startup."""
        return await self._required_repository().get(exception_id)

    async def create(self, record: ExceptionRecord) -> ExceptionRecord:
        """Forward one repository create after startup."""
        return await self._required_repository().create(record)

    async def transition(
        self,
        exception_id: str,
        expected: set[ExceptionState],
        target: ExceptionState,
        *,
        summary: str | None = None,
        failure_reason: str | None = None,
        handling_class: str | None = None,
        next_step: str | None = None,
        rejection_reason: str | None = None,
    ) -> ExceptionRecord:
        """Forward one repository transition after startup."""
        return await self._required_repository().transition(
            exception_id,
            expected,
            target,
            summary=summary,
            failure_reason=failure_reason,
            handling_class=handling_class,
            next_step=next_step,
            rejection_reason=rejection_reason,
        )

    async def record(
        self,
        event: AuditEvent | str,
        *,
        exception_id: str,
        details: Mapping[str, object] | None = None,
    ) -> AuditRecord:
        """Forward one audit event to the sink composed at startup."""
        if self.audit is None:
            raise RuntimeError("audit sink is not initialized")
        return await self.audit.record(event, exception_id=exception_id, details=details)

    async def publish(self, job: ExceptionJob) -> str:
        """Forward one queue publication after startup."""
        if self.queue is None:
            raise RuntimeError("job queue is not initialized")
        return await self.queue.publish(job)

    async def read(self, *, block_ms: int = 1000) -> JobDelivery | None:
        """Forward a queue read when a consumer composition uses these bindings."""
        return await self._required_queue().read(block_ms=block_ms)

    async def claim_stale(self, *, minimum_idle_ms: int) -> JobDelivery | None:
        """Forward stale-delivery recovery when a consumer uses these bindings."""
        return await self._required_queue().claim_stale(minimum_idle_ms=minimum_idle_ms)

    async def acknowledge(self, message_id: str) -> None:
        """Forward one queue acknowledgement."""
        await self._required_queue().acknowledge(message_id)

    async def queue_depth(self) -> int:
        """Forward the queue-depth diagnostic."""
        return await self._required_queue().queue_depth()

    async def pending_count(self) -> int:
        """Forward the pending-delivery diagnostic."""
        return await self._required_queue().pending_count()

    async def search_hybrid(self, request: RetrievalRequest) -> RetrievalResult:
        """Forward one hybrid retrieval request after startup."""
        if self.retriever is None:
            raise RuntimeError("retriever is not initialized")
        return await self.retriever.search_hybrid(request)

    async def list_corpus_keys(self, prefix: str) -> list[str]:
        """Forward one object-store listing so no route touches a cloud SDK."""
        if self.object_store is None:
            raise RuntimeError("object store is not initialized")
        return await self.object_store.list_keys(prefix)

    async def claim(self, key: str, operation_id: str) -> IdempotencyClaim:
        """Forward one idempotency claim after startup."""
        return await self._required_idempotency().claim(key, operation_id)

    async def complete(self, key: str, operation_id: str, response: StoredResponse) -> None:
        """Forward one idempotency completion after startup."""
        await self._required_idempotency().complete(key, operation_id, response)

    async def release(self, key: str, operation_id: str) -> None:
        """Forward one idempotency release after startup."""
        await self._required_idempotency().release(key, operation_id)

    def _required_idempotency(self) -> IdempotencyStore:
        """Return the initialized idempotency store or fail with a startup defect."""
        if self.idempotency_store is None:
            raise RuntimeError("idempotency store is not initialized")
        return self.idempotency_store

    async def ready(self) -> bool:
        """Return true only when every required API dependency answers.

        Readiness is intentionally stricter than liveness. Sprint 2 adds the
        object-storage dependency, and the corpus schema must exist as well: a
        process that answers while its retrieval tables are missing is not
        usable, so any dependency error returns ``False`` and Compose and
        students receive a stable 503 response. Task 3.3 replaces the Redis
        Streams reachability check with the same check against whichever
        ``JobQueue`` adapter is actually composed, so readiness keeps proving
        the transport that carries production traffic rather than a retired one.
        """
        if self.pool is None or self.queue is None or self.object_store is None:
            return False
        # A release that is still warming up is alive but not ready. Task 3.1 uses this
        # distinction: liveness never sees it, readiness always does.
        if not self.warmed_up():
            return False
        try:
            database_ready = await self.pool.fetchval("SELECT 1") == 1
            corpus_ready = (
                await self.pool.fetchval("SELECT to_regclass('public.chunks')") is not None
            )
            await self.queue.queue_depth()
            await self.object_store.list_keys("corpus/")
        except Exception:
            return False
        return database_ready and corpus_ready

    def _required_repository(self) -> ExceptionRepository:
        """Return the initialized repository or fail with a startup defect."""
        if self.repository is None:
            raise RuntimeError("exception repository is not initialized")
        return self.repository

    def _required_queue(self) -> JobQueue:
        """Return the initialized job queue or fail with a startup defect."""
        if self.queue is None:
            raise RuntimeError("job queue is not initialized")
        return self.queue
