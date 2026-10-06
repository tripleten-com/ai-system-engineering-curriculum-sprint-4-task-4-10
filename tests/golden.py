"""Coldline.

===================

File:              tests/golden.py
Component:         Golden evaluation set
Purpose:           Load the published query set and its structurally derived relevance labels.
Interacts With:    infra/corpus fixtures and the running retrieval API
Sprint/Task:       Sprint 2 — Project 2
Concepts:          Binary relevance, structural derivation, deterministic evaluation
Tools:             Python 3.12, httpx
"""

import json
from dataclasses import dataclass
from pathlib import Path

import httpx

from tests.runtime_config import host_port

TASK_ROOT = Path(__file__).resolve().parents[1]
QUERIES_PATH = TASK_ROOT / "infra/corpus/queries.jsonl"
DOCUMENTS_PATH = TASK_ROOT / "infra/corpus/documents.jsonl"


@dataclass(frozen=True)
class GoldenQuery:
    """One published query and the document its answer must come from.

    Relevance is *structurally derived*: the label is "every chunk of
    ``target_document_id`` is relevant, and no other chunk is". Nobody scored
    passages by hand, so the labels cannot drift from the corpus, and a
    reviewer can re-derive them from the two fixture files alone.
    """

    query_id: str
    text: str
    tenant_id: str
    clearance: str
    target_document_id: str


def load_queries() -> list[GoldenQuery]:
    """Return the published golden query set in file order."""
    queries = [_query(payload) for payload in _json_lines(QUERIES_PATH)]
    known = {str(payload["document_id"]) for payload in _json_lines(DOCUMENTS_PATH)}
    unknown = sorted(
        query.target_document_id for query in queries if query.target_document_id not in known
    )
    if unknown:
        raise ValueError(f"golden set targets documents that are not in the corpus: {unknown}")
    identifiers = [query.query_id for query in queries]
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("golden set repeats a query identifier")
    return queries


def _query(payload: dict[str, object]) -> GoldenQuery:
    """Build one golden query from a fixture line, failing on a bad shape."""
    authorization = payload["authorization"]
    if not isinstance(authorization, dict):
        raise ValueError(f"query {payload.get('query_id')!r} has no authorization mapping")
    return GoldenQuery(
        query_id=str(payload["query_id"]),
        text=str(payload["text"]),
        tenant_id=str(authorization["tenant_id"]),
        clearance=str(authorization["clearance"]),
        target_document_id=str(payload["target_document_id"]),
    )


def query_ids() -> list[str]:
    """Return every published query identifier."""
    return [query.query_id for query in load_queries()]


def api_base_url() -> str:
    """Return the API base URL, honoring the documented host-port override."""
    return f"http://localhost:{host_port('COLDLINE_API_HOST_PORT', 8000)}"


def search(client: httpx.Client, query: GoldenQuery, *, explain: bool = False) -> dict[str, object]:
    """Run one golden query against the running retrieval API."""
    response = client.post(
        f"{api_base_url()}/api/v1/retrieval/search",
        json={
            "query_id": query.query_id,
            "text": query.text,
            "authorization": {"tenant_id": query.tenant_id, "clearance": query.clearance},
            "explain": explain,
        },
    )
    response.raise_for_status()
    payload: dict[str, object] = response.json()
    return payload


def retrieved_documents(payload: dict[str, object]) -> list[str]:
    """Return the document identifiers of one response, in rank order."""
    results = payload["results"]
    assert isinstance(results, list)
    return [str(item["document_id"]) for item in results]


def is_success(query: GoldenQuery, payload: dict[str, object]) -> bool:
    """Apply the published success criterion to one response.

    Success criterion: the query's target document appears at least once in
    the final ranked results. Nothing about score magnitude is asserted.
    """
    return query.target_document_id in retrieved_documents(payload)


def is_miss(query: GoldenQuery, payload: dict[str, object]) -> bool:
    """Apply the published miss criterion to one response.

    Miss criterion: the query's target document appears nowhere in the final
    ranked results.
    """
    return not is_success(query, payload)


def relevant_chunks(query: GoldenQuery, payload: dict[str, object]) -> list[str]:
    """Return the retrieved chunk identifiers whose document is the target."""
    results = payload["results"]
    assert isinstance(results, list)
    return [
        str(item["chunk_id"])
        for item in results
        if str(item["document_id"]) == query.target_document_id
    ]


def total_relevant_chunks(query: GoldenQuery, chunk_counts: dict[str, int]) -> int:
    """Return how many chunks of the target document exist in the corpus."""
    return chunk_counts[query.target_document_id]


def _json_lines(path: Path) -> list[dict[str, object]]:
    """Parse one JSON Lines fixture into mappings."""
    records: list[dict[str, object]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path.name} line {number} is not valid JSON") from exc
        records.append(record)
    return records
