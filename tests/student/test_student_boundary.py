"""Coldline.

===================

File:              tests/student/test_student_boundary.py
Component:         Student tests — Service boundary
Purpose:           Give the student a working starting point for their own boundary tests.
Interacts With:    Supplied test doubles
Sprint/Task:       Sprint 2 — Project 2 / Task 2.2
Concepts:          Independent execution, determinism
Tools:             Python 3.12, pytest

This file is yours to extend. `poe student-tests` runs it, and `poe verify`
includes that run.

The two supplied checks below prove the doubles work before you rely on them;
they touch no database and no network. Add tests for your own extracted
service here - the assessed checks in `tests/contract/` are protected and you
cannot change them.
"""

from domain.contracts import AccessTier, AuthorizationContext, RetrievalRequest
from tests.doubles import StubRetriever, candidate

CALLER = AuthorizationContext(tenant_id="tenant-double", clearance=AccessTier.STANDARD)


async def test_stub_retriever_records_the_request_it_received() -> None:
    """The double records requests, which is how you assert on request construction."""
    retriever = StubRetriever((candidate("sop-alpha#0000", 1), candidate("sop-beta#0000", 2)))

    await retriever.search_hybrid(
        RetrievalRequest(
            query_id="q-student",
            text="alpha",
            authorization=CALLER,
            top_k=2,
            dense_weight=0.5,
        )
    )

    assert retriever.requests[0].query_id == "q-student"
    assert retriever.requests[0].authorization == CALLER


async def test_stub_retriever_is_deterministic() -> None:
    """The same request twice returns the same ranking, so your tests are repeatable."""
    retriever = StubRetriever((candidate("sop-alpha#0000", 1), candidate("sop-beta#0000", 2)))
    request = RetrievalRequest(
        query_id="q-student",
        text="alpha",
        authorization=CALLER,
        top_k=1,
        dense_weight=0.5,
    )

    first = await retriever.search_hybrid(request)
    second = await retriever.search_hybrid(request)

    assert first == second
    assert [item.chunk_id for item in first.results] == ["sop-alpha#0000"]
