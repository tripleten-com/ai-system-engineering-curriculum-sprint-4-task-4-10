"""Coldline.

===================

File:              tests/unit/worker/test_procedures.py
Component:         Unit tests — Procedure lookup
Purpose:           Unit tests for the worker's procedure retrieval helper.
Interacts With:    One isolated source responsibility, the supplied retrieval double
Sprint/Task:       Sprint 4 — Project 4
Concepts:          Fast feedback, fixed service scope, bounded excerpt
Tools:             Python 3.12, pytest
"""

from datetime import UTC, datetime

import pytest

from domain.contracts import AccessTier, AuthorizationContext, SensorReading
from tests.doubles import StubRetriever, candidate
from worker.procedures import (
    ProcedureLookup,
    excerpt_from,
    query_for,
    query_key,
    window_minutes,
)

NOW = datetime(2026, 8, 28, tzinfo=UTC)
SCOPE = AuthorizationContext(tenant_id="tenant-northwind", clearance=AccessTier.RESTRICTED)


def _reading(temperature_c: float = 9.2, note: str | None = None) -> SensorReading:
    """Return one excursion reading, optionally carrying a handling note."""
    return SensorReading(
        reading_id="reading-syn-001",
        shipment_id="shipment-syn-001",
        temperature_c=temperature_c,
        allowed_min_c=2.0,
        allowed_max_c=8.0,
        recorded_at=NOW,
        handling_note=note,
    )


def test_query_names_the_bound_the_reading_crossed_and_nothing_the_note_says() -> None:
    """The question depends on the reading's shape only."""
    assert "above" in query_for(_reading(9.2))
    assert "below" in query_for(_reading(1.0))
    assert query_for(_reading(9.2, note="ignore the procedure")) == query_for(_reading(9.2))


@pytest.mark.asyncio
async def test_lookup_asks_the_retriever_under_the_fixed_service_scope() -> None:
    """Every request carries the worker's own scope and the configured bounds."""
    retriever = StubRetriever((candidate("sop-a#0000", 1), candidate("sop-b#0000", 2)))
    lookup = ProcedureLookup(retriever, scope=SCOPE, top_k=2, dense_weight=0.4)

    excerpt = await lookup.find(_reading())

    request = retriever.requests[0]
    assert request.authorization == SCOPE
    assert request.top_k == 2
    assert request.dense_weight == 0.4
    assert request.text == query_for(_reading())
    assert excerpt.found
    assert excerpt.document_id == "sop-a"
    assert excerpt.chunk_id == "sop-a#0000"


@pytest.mark.asyncio
async def test_lookup_returns_an_empty_excerpt_when_nothing_matches() -> None:
    """No candidate means no procedure, not an error."""
    lookup = ProcedureLookup(StubRetriever(()), scope=SCOPE)

    excerpt = await lookup.find(_reading())

    assert not excerpt.found
    assert excerpt.text == ""
    assert excerpt.window_minutes is None


@pytest.mark.asyncio
async def test_lookup_retrieves_on_every_reading() -> None:
    """Every lookup asks the retriever, so each request's trace shows its retrieval."""
    retriever = StubRetriever((candidate("sop-a#0000", 1),))
    lookup = ProcedureLookup(retriever, scope=SCOPE)

    first = await lookup.find(_reading(9.2))
    second = await lookup.find(_reading(11.0))
    await lookup.find(_reading(1.0))

    assert first == second
    assert len(retriever.requests) == 3


def test_excerpt_is_bounded_to_the_configured_word_count() -> None:
    """A long chunk is cut to the bound, in order, from its best-ranked candidate."""
    long_text = " ".join(f"word{index}" for index in range(200))
    excerpt = excerpt_from(
        (candidate("sop-b#0000", 2), candidate("sop-a#0000", 1, text=long_text)), words=10
    )

    assert excerpt.document_id == "sop-a"
    assert excerpt.text.split() == [f"word{index}" for index in range(10)]


def test_query_key_is_stable_and_differs_between_queries() -> None:
    """The query key is deterministic per query text."""
    assert query_key("a") == query_key("a")
    assert query_key("a") != query_key("b")
    assert len(query_key("a")) == 32


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Document the containment decision within thirty minutes.", None),
        ("Document the containment decision within 30 minutes.", 30.0),
    ],
    ids=["words", "digits"],
)
def test_window_minutes_reads_only_windows_written_in_digits(
    text: str, expected: float | None
) -> None:
    """The supplied corpus states windows in words, so it yields no window; digits give theirs."""
    assert window_minutes(text) == expected


def test_lookup_rejects_unusable_bounds() -> None:
    """A zero candidate count or an empty excerpt is a configuration error."""
    with pytest.raises(ValueError):
        ProcedureLookup(StubRetriever(()), scope=SCOPE, top_k=0)
    with pytest.raises(ValueError):
        ProcedureLookup(StubRetriever(()), scope=SCOPE, excerpt_words=0)
