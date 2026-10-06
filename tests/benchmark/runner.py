"""Coldline.

===================

File:              tests/benchmark/runner.py
Component:         Benchmark — Evaluation harness
Purpose:           Measure one retrieval configuration against the golden evaluation set.
Interacts With:    The running experiment endpoint, the golden set, the cached judge
Sprint/Task:       Sprint 2 — Project 2 / Task 2.7
Concepts:          Controlled measurement, warmup, percentiles, deterministic metrics
Tools:             Python 3.12, httpx
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from time import perf_counter

import httpx

from tests.benchmark.config import RetrievalConfig
from tests.benchmark.judge import CachedJudge, load_judge
from tests.benchmark.metrics import mean, percentile, recall_at_k, rounded
from tests.golden import GoldenQuery, api_base_url, load_queries

TASK_ROOT = Path(__file__).resolve().parents[2]
DOCUMENTS_PATH = TASK_ROOT / "infra/corpus/documents.jsonl"
QUERIES_PATH = TASK_ROOT / "infra/corpus/queries.jsonl"
REPORT_DIRECTORY = TASK_ROOT / ".benchmark"
EXPERIMENT_PATH = "/api/v1/experiments/retrieval"

# The first requests of a run pay for connection setup, query planning, byte
# compilation, and cache population. Measuring them would report the cost of
# starting up rather than the cost of retrieving, so they are executed against
# every configuration and discarded.
WARMUP_REQUESTS = 22
# Each published query is measured this many times under each configuration.
# The percentiles are taken over every sample from every query, so the reported
# tail reflects the whole golden set rather than one slow query.
REPEATS_PER_QUERY = 15
LATENCY_PLACES = 1
# Two units of the last published latency place (0.1 ms): the smallest latency
# difference the report can express at all.
LATENCY_RESOLUTION_MS = 0.2
CHUNK_WORDS = 28


@dataclass(frozen=True)
class QueryOutcome:
    """What one configuration retrieved for one published query."""

    query_id: str
    retrieved_chunk_ids: list[str]
    relevant_retrieved: int
    total_relevant: int
    recall: float
    judge_relevance: float
    judge_faithfulness: float
    unjudged_chunk_ids: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ArmReport:
    """One configuration measured against the whole golden evaluation set."""

    arm: str
    config: dict[str, float]
    golden_set_digest: str
    query_ids: list[str]
    failed_query_ids: list[str]
    recall_at_k: float
    judge_relevance: float
    judge_faithfulness: float
    latency_p50_ms: float
    latency_p95_ms: float
    latency_p99_ms: float
    latency_samples: int
    queries: list[QueryOutcome]

    @property
    def latency_spread_ms(self) -> float:
        """Return the arm's own p50-to-p95 spread, the harness's measured noise.

        This is the tolerance the adoption policy uses. It is a property of
        this measurement, not a service-level target: a difference between two
        arms that is smaller than the variation inside one arm is not evidence
        that latency changed.
        """
        spread = round(self.latency_p95_ms - self.latency_p50_ms, LATENCY_PLACES)
        return max(spread, LATENCY_RESOLUTION_MS)

    def as_document(self) -> dict[str, object]:
        """Return the report as a plain JSON-compatible mapping."""
        document = asdict(self)
        document["latency_tolerance_ms"] = self.latency_spread_ms
        return document


def golden_set_digest() -> str:
    """Return a digest over the exact golden evaluation set both arms use.

    Both arms must run against the identical golden set for the comparison to
    mean anything. Recording a digest of the two fixture files makes that
    checkable rather than assumed.
    """
    digest = hashlib.sha256()
    for path in (QUERIES_PATH, DOCUMENTS_PATH):
        digest.update(path.read_bytes())
    return digest.hexdigest()


def chunk_counts() -> dict[str, int]:
    """Return how many chunks each corpus document is split into.

    Derived from the committed corpus with the runtime's own fixed-width rule,
    so the denominator of Recall@K comes from the published fixtures rather
    than from whatever happens to be in the database.
    """
    counts: dict[str, int] = {}
    for line in DOCUMENTS_PATH.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        words = len(str(record["body"]).split())
        counts[str(record["document_id"])] = max(1, -(-words // CHUNK_WORDS))
    return counts


def _measure(
    client: httpx.Client, query: GoldenQuery, config: RetrievalConfig
) -> tuple[dict[str, object], float]:
    """Run one query under one configuration and return the payload and its latency."""
    started = perf_counter()
    response = client.post(
        f"{api_base_url()}{EXPERIMENT_PATH}",
        json={
            "query_id": query.query_id,
            "text": query.text,
            "authorization": {"tenant_id": query.tenant_id, "clearance": query.clearance},
            "top_k": config.top_k,
            "fusion_weight": config.fusion_weight,
        },
    )
    elapsed_ms = (perf_counter() - started) * 1000.0
    response.raise_for_status()
    payload: dict[str, object] = response.json()
    return payload, elapsed_ms


def _outcome(
    query: GoldenQuery,
    payload: dict[str, object],
    counts: dict[str, int],
    judge: CachedJudge,
) -> QueryOutcome:
    """Score one response against the published labels and the cached judge."""
    results = payload["results"]
    assert isinstance(results, list)
    chunk_ids = [str(item["chunk_id"]) for item in results]
    relevant = [
        str(item["chunk_id"])
        for item in results
        if str(item["document_id"]) == query.target_document_id
    ]
    total_relevant = counts[query.target_document_id]

    relevance: list[float] = []
    faithfulness: list[float] = []
    unjudged: list[str] = []
    for chunk_id in chunk_ids:
        score = judge.relevance(query.query_id, chunk_id)
        trust = judge.faithfulness(query.query_id, chunk_id)
        if score is None or trust is None:
            unjudged.append(chunk_id)
            continue
        relevance.append(score)
        faithfulness.append(trust)

    return QueryOutcome(
        query_id=query.query_id,
        retrieved_chunk_ids=chunk_ids,
        relevant_retrieved=len(relevant),
        total_relevant=total_relevant,
        recall=rounded(recall_at_k(len(relevant), total_relevant)),
        judge_relevance=rounded(mean(relevance)),
        judge_faithfulness=rounded(mean(faithfulness)),
        unjudged_chunk_ids=unjudged,
    )


def measure_arms(configs: dict[str, RetrievalConfig]) -> dict[str, ArmReport]:
    """Measure several configurations against the whole golden evaluation set.

    The arms are *interleaved*: every repeat of every query is measured under
    each configuration before moving on. Measuring one arm to completion and
    then the other would charge whichever went first for the connection pool
    warming up, and would let any drift during the run - a background process,
    a checkpoint, a throttled container - land on one side of the comparison
    and not the other. Interleaving makes those costs common to both arms
    instead of a difference between them.
    """
    queries = load_queries()
    counts = chunk_counts()
    judge = load_judge()
    names = list(configs)
    samples: dict[str, list[float]] = {name: [] for name in names}
    payloads: dict[tuple[str, str], dict[str, object]] = {}
    failed: dict[str, set[str]] = {name: set() for name in names}

    with httpx.Client(timeout=30.0) as client:
        for index in range(WARMUP_REQUESTS):
            for name in names:
                _measure(client, queries[index % len(queries)], configs[name])
        for _ in range(REPEATS_PER_QUERY):
            for query in queries:
                for name in names:
                    if query.query_id in failed[name]:
                        continue
                    try:
                        payload, elapsed_ms = _measure(client, query, configs[name])
                    except httpx.HTTPError:
                        failed[name].add(query.query_id)
                        continue
                    samples[name].append(elapsed_ms)
                    payloads[name, query.query_id] = payload

    reports: dict[str, ArmReport] = {}
    for name in names:
        outcomes = [
            _outcome(query, payloads[name, query.query_id], counts, judge)
            for query in queries
            if (name, query.query_id) in payloads
        ]
        reports[name] = ArmReport(
            arm=name,
            config=configs[name].as_mapping(),
            golden_set_digest=golden_set_digest(),
            query_ids=[query.query_id for query in queries],
            failed_query_ids=sorted(failed[name]),
            recall_at_k=rounded(mean([outcome.recall for outcome in outcomes])),
            judge_relevance=rounded(mean([outcome.judge_relevance for outcome in outcomes])),
            judge_faithfulness=rounded(mean([outcome.judge_faithfulness for outcome in outcomes])),
            latency_p50_ms=round(percentile(samples[name], 0.50), LATENCY_PLACES),
            latency_p95_ms=round(percentile(samples[name], 0.95), LATENCY_PLACES),
            latency_p99_ms=round(percentile(samples[name], 0.99), LATENCY_PLACES),
            latency_samples=len(samples[name]),
            queries=outcomes,
        )
    return reports


def impacted_query_ids(baseline: ArmReport, experiment: ArmReport) -> list[str]:
    """Return the queries the parameter change actually affected.

    A query is impacted when the configuration change altered either what was
    retrieved for it or its deterministic recall. A regression test written
    against a query nothing happened to would guard nothing this experiment
    touched.
    """
    before = {outcome.query_id: outcome for outcome in baseline.queries}
    changed: list[str] = []
    for outcome in experiment.queries:
        previous = before.get(outcome.query_id)
        if previous is None:
            continue
        if (
            previous.retrieved_chunk_ids != outcome.retrieved_chunk_ids
            or previous.recall != outcome.recall
        ):
            changed.append(outcome.query_id)
    return changed
