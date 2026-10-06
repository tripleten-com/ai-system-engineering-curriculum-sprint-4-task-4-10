"""Coldline.

===================

File:              tests/diagnostics/inspect.py
Component:         Diagnostics — Intermediate stage inspector
Purpose:           Print the per-stage evidence for one query and its target chunk.
Interacts With:    The running retrieval API and the committed corpus fixtures
Sprint/Task:       Sprint 2 — Project 2 / Task 2.8
Concepts:          Intermediate telemetry, root-cause isolation
Tools:             Python 3.12, httpx

Supplied and protected. This prints evidence. It does not name a stage, and it
does not tell you which answer to record: reading the evidence and deciding
what it supports is the Task.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

import httpx

from domain.contracts import RetrievalStage
from tests.diagnostics.attribution import (
    ChunkFacts,
    CustodyFacts,
    StageObservation,
    chunk_facts,
    custody_facts,
    custody_lines,
    evidence_lines,
)
from tests.golden import api_base_url

TASK_ROOT = Path(__file__).resolve().parents[2]
DOCUMENTS_PATH = TASK_ROOT / "infra/corpus/documents.jsonl"
QUERIES_PATH = TASK_ROOT / "infra/corpus/queries.jsonl"
PROVENANCE_PATH = TASK_ROOT / "infra/corpus/provenance.jsonl"
INVESTIGATION_PATH = TASK_ROOT / "infra/corpus/investigation.jsonl"
CHUNK_WORDS = 28


@dataclass(frozen=True)
class Investigation:
    """One query under investigation and the chunk that should answer it."""

    query_id: str
    text: str
    tenant_id: str
    clearance: str
    target_chunk_id: str
    expected_readable: bool
    note: str

    @property
    def target_document_id(self) -> str:
        """Return the document the target chunk belongs to."""
        return self.target_chunk_id.split("#", maxsplit=1)[0]


def _json_lines(path: Path) -> list[dict[str, object]]:
    """Parse one JSON Lines fixture."""
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def load_investigations() -> list[Investigation]:
    """Return every designated investigation, in file order."""
    records: list[Investigation] = []
    for payload in _json_lines(INVESTIGATION_PATH):
        authorization = payload["authorization"]
        if not isinstance(authorization, dict):
            raise ValueError(f"{payload.get('query_id')!r} has no authorization mapping")
        records.append(
            Investigation(
                query_id=str(payload["query_id"]),
                text=str(payload["text"]),
                tenant_id=str(authorization["tenant_id"]),
                clearance=str(authorization["clearance"]),
                target_chunk_id=str(payload["target_chunk_id"]),
                # Whether this caller is *supposed* to be able to read the
                # target. It is what separates a defect from the boundary
                # working, and the rule reaches the same conclusion from the
                # custody records rather than taking this field's word for it -
                # the two are compared by a supplied check.
                expected_readable=bool(payload["expected_readable"]),
                note=str(payload["note"]),
            )
        )
    if not records:
        raise ValueError("investigation.jsonl names no query")
    return records


def designated_investigation() -> Investigation:
    """Return the single designated miss investigation for this Task."""
    return load_investigations()[0]


def chunk_texts(document_id: str) -> dict[str, str]:
    """Return one document's chunks, split by the runtime's own fixed-width rule."""
    for record in _json_lines(DOCUMENTS_PATH):
        if str(record["document_id"]) != document_id:
            continue
        words = str(record["body"]).split()
        return {
            f"{document_id}#{index:04d}": " ".join(words[offset : offset + CHUNK_WORDS])
            for index, offset in enumerate(range(0, len(words), CHUNK_WORDS))
        }
    raise ValueError(f"{document_id} is not in the supplied corpus")


def document_title(document_id: str) -> str:
    """Return one corpus document's title."""
    for record in _json_lines(DOCUMENTS_PATH):
        if str(record["document_id"]) == document_id:
            return str(record["title"])
    raise ValueError(f"{document_id} is not in the supplied corpus")


def search(client: httpx.Client, investigation: Investigation) -> dict[str, object]:
    """Run one investigation query with the stage evidence turned on."""
    response = client.post(
        f"{api_base_url()}/api/v1/retrieval/search",
        json={
            "query_id": investigation.query_id,
            "text": investigation.text,
            "authorization": {
                "tenant_id": investigation.tenant_id,
                "clearance": investigation.clearance,
            },
            # Without this the authorization stage reports only its decision,
            # not the readable pool the decision produced, and "was this chunk
            # readable at all" would be unanswerable.
            "explain": True,
        },
    )
    response.raise_for_status()
    payload: dict[str, object] = response.json()
    return payload


def observe(investigation: Investigation, payload: dict[str, object]) -> StageObservation:
    """Turn one API response into the stage observation the rule reads."""
    stages = payload["stages"]
    assert isinstance(stages, list)
    by_stage = {str(stage["stage"]): stage for stage in stages}
    missing = sorted({stage.value for stage in RetrievalStage} - set(by_stage))
    if missing:
        raise ValueError(f"the response carries no evidence for these stages: {missing}")

    def admitted(stage: RetrievalStage) -> tuple[str, ...]:
        return tuple(str(item) for item in by_stage[stage.value]["admitted"])

    def dropped(stage: RetrievalStage) -> tuple[str, ...]:
        return tuple(str(item) for item in by_stage[stage.value]["dropped"])

    results = payload["results"]
    assert isinstance(results, list)
    return StageObservation(
        target_chunk_id=investigation.target_chunk_id,
        readable_pool=admitted(RetrievalStage.AUTHORIZATION),
        authorization_dropped=dropped(RetrievalStage.AUTHORIZATION),
        dense_candidates=admitted(RetrievalStage.DENSE),
        sparse_candidates=admitted(RetrievalStage.SPARSE),
        fusion_input=admitted(RetrievalStage.FUSION) + dropped(RetrievalStage.FUSION),
        final_results=tuple(str(item["chunk_id"]) for item in results),
    )


def facts_for(investigation: Investigation) -> ChunkFacts:
    """Return the chunking evidence for one investigation."""
    document_id = investigation.target_document_id
    return chunk_facts(
        query_text=investigation.text,
        document_id=document_id,
        title=document_title(document_id),
        chunk_texts=chunk_texts(document_id),
    )


def _tenant_id(access: object) -> str:
    """Return one document's labelled tenancy from its access mapping."""
    if not isinstance(access, dict):
        raise ValueError("a corpus document has no access mapping")
    return str(access["tenant_id"])


def custody_for(investigation: Investigation) -> CustodyFacts:
    """Return the custody evidence for one investigation's target document.

    Both fixtures are read whole, because the evidence is comparative: what
    makes one label wrong is that every other document from the same custodian
    is labelled differently.
    """
    labels = {
        str(record["document_id"]): _tenant_id(record["access"])
        for record in _json_lines(DOCUMENTS_PATH)
    }
    provenance = _json_lines(PROVENANCE_PATH)
    return custody_facts(
        document_id=investigation.target_document_id,
        labels=labels,
        custodians={str(record["document_id"]): str(record["custodian"]) for record in provenance},
        source_uris={
            str(record["document_id"]): str(record["source_uri"]) for record in provenance
        },
    )


def _report(investigation: Investigation, payload: dict[str, object]) -> None:
    """Print the intermediate breakdown for one investigation."""
    observation = observe(investigation, payload)
    facts = facts_for(investigation)
    custody = custody_for(investigation)

    print(f"query        {investigation.query_id}")
    print(f"text         {investigation.text!r}")
    print(f"caller       tenant={investigation.tenant_id} clearance={investigation.clearance}")
    print(f"target chunk {investigation.target_chunk_id}")
    print(f"expected     readable by this caller: {investigation.expected_readable}")
    print(f"outcome      {'retrieved' if observation.retrieved else 'MISS'}")
    print(f"note         {investigation.note}")
    print()
    print("Per-stage evidence")
    for line in evidence_lines(observation, facts):
        print(f"  {line}")
    for line in custody_lines(custody):
        print(f"  {line}")
    print()

    stages = payload["stages"]
    assert isinstance(stages, list)
    for stage in stages:
        print(f"  [{stage['stage']}] {stage['note']}")
        print(f"    admitted: {', '.join(str(item) for item in stage['admitted']) or '(none)'}")
        if stage["dropped"]:
            print(f"    dropped : {', '.join(str(item) for item in stage['dropped'])}")
    print()
    print(f"  chunks of {facts.document_id}:")
    texts = chunk_texts(facts.document_id)
    print("    Query terms use normalized title + body tokens, as in the stage summary.")
    for chunk_id, terms in zip(facts.chunk_ids, facts.terms_per_chunk, strict=True):
        text = texts[chunk_id]
        held = sorted(facts.shared_terms & terms)
        print(f"    {chunk_id}  query terms present: {held or '(none)'}")
        print(f"      {text}")
    print()
    rule = "docs/student/task-2-8-contract.md"
    if not (TASK_ROOT / rule).is_file():
        rule = "tests/diagnostics/attribution.py"
    print("Attribute the miss to the one stage this evidence isolates, and rule out a stage")
    print(f"this evidence proves operated normally. {rule} states the")
    print("supplied rule for both; use your current Task contract for the deliverable.")


def main() -> int:
    """Print the intermediate stage breakdown for the designated investigations."""
    selected = sys.argv[1:]
    try:
        investigations = load_investigations()
    except (OSError, ValueError) as exc:
        print(f"investigation fixture is unusable: {exc}", file=sys.stderr)
        return 1
    if selected:
        investigations = [item for item in investigations if item.query_id in selected]
        if not investigations:
            print(f"no designated investigation named {selected}", file=sys.stderr)
            return 1

    try:
        with httpx.Client(timeout=30.0) as client:
            payloads = [(item, search(client, item)) for item in investigations]
    except httpx.HTTPError as exc:
        print(f"diagnostic could not reach {api_base_url()}: {exc}", file=sys.stderr)
        print(
            "Start the stack with `poe start` and ingest with `poe ingest` first.",
            file=sys.stderr,
        )
        return 1

    for index, (investigation, payload) in enumerate(payloads):
        if index:
            print("=" * 78)
        _report(investigation, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
