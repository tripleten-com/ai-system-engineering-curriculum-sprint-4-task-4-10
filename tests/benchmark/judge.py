"""Coldline.

===================

File:              tests/benchmark/judge.py
Component:         Benchmark — Cached judge evidence
Purpose:           Read the cached, comparison-only judge evaluations.
Interacts With:    infra/judge/cached-judgements.jsonl
Sprint/Task:       Sprint 2 — Project 2 / Task 2.7
Concepts:          Model-based evaluation, comparison-only evidence, caching
Tools:             Python 3.12
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

TASK_ROOT = Path(__file__).resolve().parents[2]
JUDGEMENTS_PATH = TASK_ROOT / "infra/judge/cached-judgements.jsonl"


class JudgeEvidenceError(ValueError):
    """Report one unusable cached judge fixture."""


@dataclass(frozen=True)
class Judgement:
    """One cached judgement of one chunk against one query."""

    query_id: str
    chunk_id: str
    relevance: float
    faithfulness: float
    judge: str


class CachedJudge:
    """Answer judgement lookups from the committed fixture, and nothing else.

    There is no network path in this class on purpose. The Task forbids a live
    or billable model call during evaluation, and the only way to keep that
    guarantee auditable is for the evidence to have one source: a file.
    """

    def __init__(self, judgements: list[Judgement]) -> None:
        """Index the cached judgements by query and chunk."""
        self._by_pair = {(item.query_id, item.chunk_id): item for item in judgements}
        self._judges = sorted({item.judge for item in judgements})

    @property
    def judge_identities(self) -> list[str]:
        """Return every judge identity present in the fixture."""
        return list(self._judges)

    def relevance(self, query_id: str, chunk_id: str) -> float | None:
        """Return the cached relevance, or None when this pair was never judged."""
        item = self._by_pair.get((query_id, chunk_id))
        return None if item is None else item.relevance

    def faithfulness(self, query_id: str, chunk_id: str) -> float | None:
        """Return the cached faithfulness, or None when this pair was never judged."""
        item = self._by_pair.get((query_id, chunk_id))
        return None if item is None else item.faithfulness

    def judged_chunks(self, query_id: str) -> list[str]:
        """Return every chunk this query has a cached judgement for."""
        return sorted(chunk for query, chunk in self._by_pair if query == query_id)


def load_judge() -> CachedJudge:
    """Load the committed cached judge evidence."""
    judgements: list[Judgement] = []
    text = JUDGEMENTS_PATH.read_text(encoding="utf-8")
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise JudgeEvidenceError(
                f"{JUDGEMENTS_PATH.name} line {number} is not valid JSON"
            ) from exc
        judgements.append(_judgement(record, number))
    if not judgements:
        raise JudgeEvidenceError(f"{JUDGEMENTS_PATH.name} contains no judgements")
    return CachedJudge(judgements)


def _judgement(record: dict[str, object], number: int) -> Judgement:
    """Build one judgement, failing on a shape the comparison cannot use."""
    try:
        relevance = float(record["relevance"])  # type: ignore[arg-type]
        faithfulness = float(record["faithfulness"])  # type: ignore[arg-type]
    except (KeyError, TypeError, ValueError) as exc:
        raise JudgeEvidenceError(
            f"{JUDGEMENTS_PATH.name} line {number} has no numeric relevance and faithfulness"
        ) from exc
    for label, score in (("relevance", relevance), ("faithfulness", faithfulness)):
        if not 0.0 <= score <= 1.0:
            raise JudgeEvidenceError(
                f"{JUDGEMENTS_PATH.name} line {number}: {label} {score} is outside 0.0 to 1.0"
            )
    return Judgement(
        query_id=str(record["query_id"]),
        chunk_id=str(record["chunk_id"]),
        relevance=relevance,
        faithfulness=faithfulness,
        judge=str(record["judge"]),
    )
