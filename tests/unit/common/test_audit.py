"""Coldline.

===================

File:              tests/unit/common/test_audit.py
Component:         Unit tests — Audit sink
Purpose:           Prove the sink fills in the trace id and the time, stores details as given,
                    renders records whole, and that the memory store keeps them in order.
Interacts With:    src/common/audit.py, tests/security/harness.py (MemoryAuditStore)
Sprint/Task:       Sprint 4 — Project 4 / Task 4.3
Concepts:          Audit records, trace correlation, evidence without filtering
Tools:             Python 3.12, pytest, OpenTelemetry
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

import pytest
from opentelemetry.trace import NonRecordingSpan, SpanContext, TraceFlags, use_span

from common.audit import (
    STORED_OUTCOME_STATES,
    WORKER_SEQUENCE,
    AuditEvent,
    AuditRecord,
    AuditSink,
    answer_digest,
    current_trace_id,
)
from domain.contracts import ExceptionState
from tests.security.harness import MemoryAuditStore

NOW = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
TRACE_ID = 0x0123456789ABCDEF0123456789ABCDEF


def _span() -> NonRecordingSpan:
    """Return a span with a known, valid trace id and no SDK behind it."""
    return NonRecordingSpan(
        SpanContext(
            trace_id=TRACE_ID,
            span_id=0x0123456789ABCDEF,
            is_remote=False,
            trace_flags=TraceFlags(TraceFlags.SAMPLED),
        )
    )


def test_the_event_names_and_the_worker_order_are_the_documented_ones() -> None:
    """The enum and the sequence are what docs/security/audit-events.md lists."""
    assert [event.value for event in AuditEvent] == [
        "processing_requested",
        "model_responded",
        "output_validated",
        "output_rejected",
        "outcome_stored",
        "summary_read",
    ]
    assert [sorted(step) for step in WORKER_SEQUENCE] == [
        ["processing_requested"],
        ["model_responded"],
        ["output_rejected", "output_validated"],
        ["outcome_stored"],
    ]
    assert STORED_OUTCOME_STATES == {ExceptionState.COMPLETED, ExceptionState.NEEDS_REVIEW}


def test_the_answer_digest_is_sha256_of_the_text() -> None:
    """The model-response event carries this in place of the answer."""
    assert answer_digest("abc") == hashlib.sha256(b"abc").hexdigest()
    assert len(answer_digest("")) == 64


def test_the_trace_id_is_the_current_spans_or_none() -> None:
    """Inside a span the id is 32 hex characters; outside any span there is none."""
    assert current_trace_id() is None
    with use_span(_span()):
        assert current_trace_id() == format(TRACE_ID, "032x")
    assert current_trace_id() is None


@pytest.mark.asyncio
async def test_the_sink_fills_in_trace_id_and_time_and_stores_details_as_given() -> None:
    """The recorder passes the event, the id and the details; the sink adds the rest."""
    store = MemoryAuditStore()
    sink = AuditSink(store, clock=lambda: NOW)

    with use_span(_span()):
        stored = await sink.record(
            AuditEvent.MODEL_RESPONDED,
            exception_id="exc-1",
            details={"provider": "deterministic-local", "answer_length": 42},
        )
    outside = await sink.record("summary_read", exception_id="exc-1")

    assert stored == AuditRecord(
        event="model_responded",
        exception_id="exc-1",
        trace_id=format(TRACE_ID, "032x"),
        recorded_at=NOW,
        details={"provider": "deterministic-local", "answer_length": 42},
        audit_id=1,
    )
    assert outside.trace_id is None and outside.audit_id == 2 and outside.details == {}
    assert await sink.trail("exc-1") == [stored, outside]


@pytest.mark.asyncio
async def test_the_sink_filters_nothing_so_a_leaked_field_is_visible() -> None:
    """A field the event list forbids is stored and rendered, which is what the checks need."""
    sink = AuditSink(MemoryAuditStore(), clock=lambda: NOW)

    leaked = await sink.record(
        AuditEvent.SUMMARY_READ,
        exception_id="exc-2",
        details={"subject": "user:dispatcher-01", "headers": {"authorization": "Bearer x"}},
    )

    assert "Bearer x" in leaked.rendered()
    assert "authorization" in leaked.rendered().lower()


@pytest.mark.asyncio
async def test_a_record_must_name_its_exception() -> None:
    """An event about no exception is a programming error, not a stored row."""
    sink = AuditSink(MemoryAuditStore())
    with pytest.raises(ValueError, match="must name the exception"):
        await sink.record(AuditEvent.OUTCOME_STORED, exception_id="")


def test_rendered_records_are_one_json_line_with_every_field() -> None:
    """The rendering the credential checks search holds keys, values, and the record's fields."""
    record = AuditRecord(
        event="output_rejected",
        exception_id="exc-3",
        trace_id=None,
        recorded_at=NOW,
        details={"reason_code": "not_json"},
        audit_id=7,
    )

    rendered = record.rendered()

    assert "\n" not in rendered
    assert json.loads(rendered) == {
        "audit_id": 7,
        "event": "output_rejected",
        "exception_id": "exc-3",
        "trace_id": None,
        "recorded_at": "2026-09-01T12:00:00+00:00",
        "details": {"reason_code": "not_json"},
    }


@pytest.mark.asyncio
async def test_the_memory_store_keeps_order_per_exception() -> None:
    """Two exceptions' records interleave in the store and separate in their trails, in order."""
    store = MemoryAuditStore()
    sink = AuditSink(store, clock=lambda: NOW)

    await sink.record("a", exception_id="exc-x")
    await sink.record("b", exception_id="exc-y")
    await sink.record("c", exception_id="exc-x")

    assert [record.event for record in store.trail_now("exc-x")] == ["a", "c"]
    assert [record.audit_id for record in store.trail_now("exc-x")] == [1, 3]
    assert [record.event for record in await store.trail("exc-y")] == ["b"]
    assert store.trail_now("exc-z") == []
