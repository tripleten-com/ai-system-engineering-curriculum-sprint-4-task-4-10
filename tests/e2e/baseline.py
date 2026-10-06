"""Coldline.

===================

File:              tests/e2e/baseline.py
Component:         Baseline retrieval evaluation
Purpose:           Run every published query and report success, miss, and stage evidence.
Interacts With:    The running retrieval API and the golden evaluation set
Sprint/Task:       Sprint 2 — Project 2
Concepts:          Deterministic evaluation, published criteria, evidence identifiers
Tools:             Python 3.12, httpx
"""

import json
import sys
from pathlib import Path

import httpx

from tests.golden import (
    api_base_url,
    is_success,
    load_queries,
    relevant_chunks,
    retrieved_documents,
    search,
)


def main() -> int:
    """Print one baseline row per published query and a closing summary.

    The report is the evidence Task 2.1 asks a student to read. Each row names
    the query, whether the published success criterion held, the target
    document, and the ranked document identifiers actually returned. Nothing
    here states a cause: attributing a miss to a stage is Task 2.8's work.
    """
    queries = load_queries()
    try:
        with httpx.Client(timeout=20.0) as client:
            responses = {query.query_id: search(client, query) for query in queries}
    except httpx.HTTPError as exc:
        print(f"baseline evaluation failed to reach {api_base_url()}: {exc}", file=sys.stderr)
        print(
            "Start the stack with `poe start` and ingest with `poe ingest` first.", file=sys.stderr
        )
        return 1

    if not any(response["results"] for response in responses.values()):
        print(
            "Every query returned zero candidates. The corpus is not ingested yet - "
            "run `poe ingest` and try again.",
            file=sys.stderr,
        )
        return 1

    print(f"Baseline retrieval evaluation against {api_base_url()}")
    print(f"{'query_id':<22} {'outcome':<8} {'target document':<30} returned documents")
    successes: list[str] = []
    misses: list[str] = []
    for query in queries:
        payload = responses[query.query_id]
        success = is_success(query, payload)
        (successes if success else misses).append(query.query_id)
        print(
            f"{query.query_id:<22} {'success' if success else 'miss':<8} "
            f"{query.target_document_id:<30} {', '.join(retrieved_documents(payload)) or '(none)'}"
        )

    print()
    print(f"Published success criterion met by {len(successes)} of {len(queries)} queries.")
    print(f"Queries meeting the published miss criterion: {', '.join(misses) or '(none)'}")
    print()
    print("Retrieved chunks of the target document, per query:")
    for query in queries:
        chunks = relevant_chunks(query, responses[query.query_id])
        print(f"  {query.query_id:<22} {', '.join(chunks) or '(none)'}")
    print()
    schema = json.loads(
        (Path(__file__).resolve().parents[2] / "docs/contracts/submission.schema.json").read_text(
            encoding="utf-8"
        )
    )
    fields = schema["properties"]["answers"].get("properties", {})
    if {"success_query_id", "miss_query_id"} <= fields.keys():
        print(
            "Record one query meeting the success criterion in answers.success_query_id and one "
            "meeting the miss criterion in answers.miss_query_id."
        )
    else:
        print(
            "Use these baseline observations for orientation; "
            "follow the current Task's answer sheet."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
