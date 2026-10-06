"""Coldline.

===================

File:              tests/regression.py
Component:         Regression suite support
Purpose:           Assert that one published query still retrieves an expected ranking.
Interacts With:    The running experiment endpoint and the experimental configuration
Sprint/Task:       Sprint 2 — Project 2 / Task 2.7
Concepts:          Regression testing, ranking assertions, deterministic evidence
Tools:             Python 3.12, httpx

Supplied and protected. Task 2.7 asks you to add one regression test case for a
query your experiment affected. Write it under `tests/student/` and make the
assertion through `assert_expected_ranking` below.

    from tests.regression import assert_expected_ranking

    def test_spill_notification_still_ranks_the_hazmat_rule() -> None:
        assert_expected_ranking(
            "q-spill-notification",
            ["rule-hazmat-spill#0000", "..."],
        )

The expected list is the *complete* ranked list of chunk identifiers the query
returns under your experimental configuration, in order. Read it from the
`retrieved_chunk_ids` field of your query in `.benchmark/experiment.json`, or
from the per-query rows `poe benchmark` prints.

Writing the whole ranking down is the point. A test that asserts only that
something came back would still pass after a change that reordered the answer,
which is the degradation a regression test exists to catch.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import httpx

from tests.benchmark.config import experiment_config
from tests.benchmark.runner import EXPERIMENT_PATH
from tests.golden import api_base_url, load_queries

TASK_ROOT = Path(__file__).resolve().parents[1]
# Where each call records itself, so the assessed checks can see which query a
# regression test actually asserted on. The assessed checks set this to a
# temporary file; a plain `poe student-tests` run writes under `.benchmark/`.
CALL_LOG = "COLDLINE_REGRESSION_CALL_LOG"
DEFAULT_CALL_LOG = TASK_ROOT / ".benchmark/regression-calls.json"


def retrieved_chunk_ids(query_id: str) -> list[str]:
    """Return the ranked chunk identifiers one published query returns now.

    The request goes through the same supplied evaluation endpoint the
    benchmark harness uses, under the experimental configuration, so a
    regression test measures the configuration the experiment adopted.
    """
    query = next((item for item in load_queries() if item.query_id == query_id), None)
    if query is None:
        raise AssertionError(
            f"{query_id!r} is not a published golden query; the golden set is "
            "infra/corpus/queries.jsonl"
        )
    config = experiment_config()
    with httpx.Client(timeout=30.0) as client:
        response = client.post(
            f"{api_base_url()}{EXPERIMENT_PATH}",
            json={
                "query_id": query.query_id,
                "text": query.text,
                "authorization": {
                    "tenant_id": query.tenant_id,
                    "clearance": query.clearance,
                },
                "top_k": config.top_k,
                "fusion_weight": config.fusion_weight,
            },
        )
    response.raise_for_status()
    payload = response.json()
    return [str(item["chunk_id"]) for item in payload["results"]]


def assert_expected_ranking(query_id: str, expected_chunk_ids: list[str]) -> None:
    """Assert one published query returns exactly this ranking, and record the call."""
    if not expected_chunk_ids:
        raise AssertionError(
            "a regression test must state the ranking it expects; an empty expectation "
            "asserts nothing"
        )
    actual = retrieved_chunk_ids(query_id)
    _record(query_id, expected_chunk_ids)
    assert actual == expected_chunk_ids, (
        f"{query_id} now returns {actual}, not the expected {expected_chunk_ids}"
    )


def _record(query_id: str, expected_chunk_ids: list[str]) -> None:
    """Append one call to the run's call log."""
    override = os.environ.get(CALL_LOG, "")
    path = Path(override) if override else DEFAULT_CALL_LOG
    path.parent.mkdir(parents=True, exist_ok=True)
    calls: list[dict[str, object]] = []
    if path.is_file():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            existing = []
        if isinstance(existing, list):
            calls = [item for item in existing if isinstance(item, dict)]
    calls.append({"query_id": query_id, "expected_chunk_ids": list(expected_chunk_ids)})
    path.write_text(json.dumps(calls, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def recorded_calls(path: Path) -> list[dict[str, object]]:
    """Return the regression assertions one run recorded."""
    if not path.is_file():
        return []
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, list):
        return []
    return [item for item in document if isinstance(item, dict)]
