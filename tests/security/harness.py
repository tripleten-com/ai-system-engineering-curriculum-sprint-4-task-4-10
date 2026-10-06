"""Coldline.

===================

File:              tests/security/harness.py
Component:         Security tooling — In-process access harness
Purpose:           Build the API from src/ in this process, with a memory store, a memory audit
                    sink, and the real verifier.
Interacts With:    src/api/routes.py, src/api/security, src/common/audit.py, config/auth.yaml,
                    tests/fixtures/tokens/fixtures.yaml, tests/security/interaction.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.3
Concepts:          Deterministic access tests, in-process HTTP, mutation-checkable routes
Tools:             Python 3.12, httpx, FastAPI, OpenTelemetry

Task 4.2's settled access tests run against this harness rather than the running container,
for one reason: the checks rerun student tests against mutated copies of ``src/``, and only
an application built in-process from ``src/`` can be pointed at such a copy. The route code,
the access rule, and the token verifier are the real ones; the exception store, queue,
retriever, and document repository are memory doubles, so a test needs PostgreSQL for
nothing. The verifier is configured from ``config/auth.yaml`` and fetches the key set from
the ``jwks_url`` it names, so the issuer container must be up.

Task 4.3 composes the application with the real ``AuditSink`` over a memory store
(``MemoryAuditStore``), so the summary-read event ``get_exception`` records lands where a
test can read it, and wraps each in-process request in a span of its own, so every event a
request records carries that request's trace id as it does in the running stack.
``tests/security/interaction.py`` extends this harness with the worker side.

When the assessed checks run a student file they set ``COLDLINE_ACCESS_TRACE``, and every
request made through ``bearer_client`` is then recorded against the pytest case that made
it: the fixture, the path, and whether the requested exception is one this harness holds
with a stored outcome (``tests/security/trace.py``). After the response, a second line
(``kind: audit``) records what the request left in this harness's audit store: how many
``summary_read`` records the exception now has and whether any of them carries the bearer
token the request sent. The mutation runner reads that line before it credits a failing
audit test under ``header-leak`` with having noticed the leaked header.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, MutableMapping
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
from fastapi import FastAPI
from opentelemetry import trace as otel_trace

from api.document_service import DocumentService
from api.retrieval_workflow import RetrievalWorkflow
from api.routes import create_app
from api.security.tokens import TokenVerifier
from api.use_cases import ReadingApplication
from common.audit import STORED_OUTCOME_STATES, AuditEvent, AuditRecord, AuditSink
from domain.contracts import (
    ExceptionJob,
    ExceptionRecord,
    ExceptionState,
    JobDelivery,
    SensorReading,
)
from tests.doubles import StubRetriever, candidate
from tests.security import trace
from tests.security.fixtures import FIXTURES_PATH, token
from tests.security.issuer_origin import host_issuer_origin

TASK_ROOT = Path(__file__).resolve().parents[2]
AUTH_CONFIG_PATH = TASK_ROOT / "config/auth.yaml"
NOW = datetime(2026, 9, 1, tzinfo=UTC)
_TRACER = otel_trace.get_tracer(__name__)


class MemoryRepository:
    """Hold exception records in a dictionary, with the repository contract's shape."""

    def __init__(self) -> None:
        """Start empty."""
        self.records: dict[str, ExceptionRecord] = {}

    async def get(self, exception_id: str) -> ExceptionRecord | None:
        """Return one stored record, or None."""
        return self.records.get(exception_id)

    async def create(self, record: ExceptionRecord) -> ExceptionRecord:
        """Create a record or return the existing one."""
        return self.records.setdefault(record.exception_id, record)

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
        """Apply one state transition to the stored record, as the PostgreSQL adapter does."""
        current = self.records[exception_id]
        if current.state not in expected:
            raise RuntimeError(f"{exception_id} is {current.state}, not in {expected}")
        updated = current.model_copy(
            update={
                "state": target,
                "summary": summary if summary is not None else current.summary,
                "failure_reason": failure_reason,
                "handling_class": (
                    handling_class if handling_class is not None else current.handling_class
                ),
                "next_step": next_step if next_step is not None else current.next_step,
                "rejection_reason": (
                    rejection_reason if rejection_reason is not None else current.rejection_reason
                ),
                "updated_at": NOW,
            }
        )
        self.records[exception_id] = updated
        return updated


class MemoryQueue:
    """Count publications instead of sending them anywhere; the rest of the port is inert."""

    def __init__(self) -> None:
        """Start at zero."""
        self.count = 0

    async def publish(self, job: ExceptionJob) -> str:
        """Record one publication and return a synthetic message id."""
        self.count += 1
        return f"memory-{self.count}"

    async def read(self, *, block_ms: int = 1000) -> JobDelivery | None:
        """Deliver nothing: no worker consumes from this harness."""
        return None

    async def claim_stale(self, *, minimum_idle_ms: int) -> JobDelivery | None:
        """Recover nothing: nothing was delivered."""
        return None

    async def acknowledge(self, message_id: str) -> None:
        """Accept any acknowledgement."""

    async def queue_depth(self) -> int:
        """Report the publications that were never consumed."""
        return self.count

    async def pending_count(self) -> int:
        """Report no in-flight delivery."""
        return 0


class MemoryAuditStore:
    """Keep audit records in a list, in the order they were appended."""

    def __init__(self) -> None:
        """Start empty."""
        self.records: list[AuditRecord] = []

    async def append(self, record: AuditRecord) -> AuditRecord:
        """Store one record with the next sequence number and return it."""
        stored = replace(record, audit_id=len(self.records) + 1)
        self.records.append(stored)
        return stored

    async def trail(self, exception_id: str) -> list[AuditRecord]:
        """Return one exception's records, oldest first."""
        return self.trail_now(exception_id)

    def trail_now(self, exception_id: str) -> list[AuditRecord]:
        """Return one exception's records without awaiting, for a test's assertions."""
        return [record for record in self.records if record.exception_id == exception_id]


async def _no_objects(prefix: str) -> list[str]:
    """Stand in for the object store: the access tests list nothing."""
    return []


class _SpanPerRequest:
    """Start one span per in-process request, so each read records its own trace id.

    The running API gets this from the FastAPI instrumentation in ``src/api/bootstrap.py``;
    ``create_app`` alone instruments nothing, so the harness adds the span the way the
    composition root would.
    """

    def __init__(self, app: FastAPI) -> None:
        """Wrap one application."""
        self._app = app

    async def __call__(
        self,
        scope: MutableMapping[str, Any],
        receive: Callable[[], Awaitable[MutableMapping[str, Any]]],
        send: Callable[[MutableMapping[str, Any]], Awaitable[None]],
    ) -> None:
        """Run the request inside a span named after its method and path."""
        if scope.get("type") != "http":
            await self._app(scope, receive, send)
            return
        name = f"{scope.get('method', 'GET')} {scope.get('path', '/')}"
        with _TRACER.start_as_current_span(name):
            await self._app(scope, receive, send)


def build_app(
    repository: MemoryRepository,
    queue: MemoryQueue,
    *,
    token_verifier: TokenVerifier,
    audit: AuditSink,
    clock: Callable[[], datetime] = lambda: NOW,
) -> FastAPI:
    """Compose the HTTP application from src/ around memory doubles, the verifier and the sink."""
    application = ReadingApplication(repository, queue, clock=clock)
    retrieval = RetrievalWorkflow(
        StubRetriever((candidate("sop-harness#0000", 1),)),
        top_k=3,
        dense_weight=0.5,
        token_budget=64,
    )
    return create_app(
        application,
        repository,
        retrieval,
        _no_objects,
        DocumentService(lambda: None),
        token_verifier=token_verifier,
        audit=audit,
    )


class AccessHarness:
    """One in-process API, its memory store, its memory audit sink, and the token fixtures."""

    def __init__(
        self,
        root: Path = TASK_ROOT,
        *,
        token_verifier: TokenVerifier | None = None,
        trace_path: Path | None = None,
        audit: AuditSink | None = None,
    ) -> None:
        """Build the application; the verifier defaults to the one config/auth.yaml configures.

        ``trace_path`` defaults to the file ``COLDLINE_ACCESS_TRACE`` names, or to no
        recording at all when the variable is unset. ``audit`` defaults to a fresh sink over
        a memory store, so each harness holds the audit records of its own tests only.
        """
        self.root = root
        self.repository = MemoryRepository()
        self.queue = MemoryQueue()
        self._audit_store = MemoryAuditStore()
        self._audit = AuditSink(self._audit_store) if audit is None else audit
        self.verifier = (
            TokenVerifier.from_config(
                root / "config/auth.yaml", jwks_origin=host_issuer_origin(root)
            )
            if token_verifier is None
            else token_verifier
        )
        self.app = build_app(
            self.repository, self.queue, token_verifier=self.verifier, audit=self._audit
        )
        self._fixtures = root / FIXTURES_PATH.relative_to(TASK_ROOT)
        self._trace = trace.trace_path() if trace_path is None else trace_path

    def token(self, name: str) -> str:
        """Return one fixture's compact token by its name."""
        return token(name, path=self._fixtures)

    def summary_reads_holding(self, exception_id: str, needle: str) -> tuple[int, bool]:
        """Return an exception's summary-read count and whether any read's details carry ``needle``.

        The needle is searched in each read's ``details`` rendered as JSON, so a header
        value nested under any key is found. This reads the harness's own memory store,
        which is the sink the route records into.
        """
        reads = [
            record
            for record in self._audit_store.trail_now(exception_id)
            if record.event == AuditEvent.SUMMARY_READ.value
        ]
        holds = any(needle in json.dumps(record.details, default=str) for record in reads)
        return len(reads), holds

    def bearer_client(self, name: str | None = None) -> httpx.AsyncClient:
        """Return an async client against the in-process API, sending one fixture as a bearer token.

        ``None`` sends no Authorization header at all. Every request the client sends is
        recorded when a trace file is configured: the fixture, the method and path, and
        whether the path names an exception this harness holds with a stored outcome;
        after the response, what the request left in the audit store.
        """
        bearer = None if name is None else self.token(name)
        headers = {} if bearer is None else {"Authorization": f"Bearer {bearer}"}

        async def record_request(request: httpx.Request) -> None:
            """Record one request against the pytest case now running."""
            exception_id = trace.exception_id_of(request.url.path)
            stored = self.repository.records.get(exception_id) if exception_id else None
            outcome = bool(
                stored is not None and stored.state in STORED_OUTCOME_STATES and stored.summary
            )
            trace.record(
                self._trace,
                {
                    "kind": "read",
                    "fixture": name,
                    "method": request.method,
                    "path": request.url.path,
                    "exception_id": exception_id,
                    "stored_summary": bool(stored is not None and stored.summary),
                    "stored_outcome": outcome,
                },
            )

        async def record_response(response: httpx.Response) -> None:
            """Record what the request left in the audit store, once it was served."""
            if self._trace is None:
                return
            exception_id = trace.exception_id_of(response.request.url.path)
            if exception_id is None:
                return
            reads, holds = self.summary_reads_holding(exception_id, bearer or "")
            trace.record(
                self._trace,
                {
                    "kind": "audit",
                    "fixture": name,
                    "exception_id": exception_id,
                    "status": response.status_code,
                    "summary_reads": reads,
                    "bearer_in_summary_read": bool(bearer) and holds,
                },
            )

        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=_SpanPerRequest(self.app)),
            base_url="http://coldline.test",
            headers=headers,
            event_hooks={"request": [record_request], "response": [record_response]},
        )

    def stored_exception(self, summary: str | None = None) -> tuple[str, str]:
        """Create one COMPLETED exception with a stored summary; return its id and that summary.

        Each call makes a fresh record with a unique id and a unique summary text, so a
        test can assert the exact summary it stored and depends on no earlier run.
        """
        suffix = uuid4().hex
        text = (
            summary
            if summary is not None
            else (
                f"Shipment shipment-{suffix[:8]} recorded 9.2 C against an allowed 2.0 to 8.0 C; "
                f"hold the pallet at the Dover relay. Summary {suffix}."
            )
        )
        reading = SensorReading(
            reading_id=f"reading-{suffix}",
            shipment_id=f"shipment-{suffix}",
            temperature_c=9.2,
            allowed_min_c=2.0,
            allowed_max_c=8.0,
            recorded_at=NOW,
            handling_note="Re-ice at the Dover relay before the pallet moves.",
        )
        exception_id = f"exc-{suffix}"
        self.repository.records[exception_id] = ExceptionRecord(
            exception_id=exception_id,
            reading=reading,
            state=ExceptionState.COMPLETED,
            accepted_at=NOW,
            updated_at=NOW,
            summary=text,
            handling_class="thermal_excursion",
            next_step="operational_review",
        )
        return exception_id, text
