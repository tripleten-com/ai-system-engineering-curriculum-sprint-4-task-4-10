"""Coldline.

===================

File:              src/domain/chunking.py
Component:         Domain — Deterministic chunking
Purpose:           Split one document into stable, identifiable retrieval chunks.
Interacts With:    Corpus ingestion and the data layer
Sprint/Task:       Sprint 2 — Project 2
Concepts:          Determinism, stable identity, provenance preservation
Tools:             Python 3.12
"""

from domain.contracts import ChunkRecord, DocumentRecord
from domain.embedding import embed

CHUNK_WORDS = 28


def chunk_document(
    document: DocumentRecord, *, chunk_words: int = CHUNK_WORDS
) -> list[ChunkRecord]:
    """Return the fixed-width, non-overlapping chunks of one document.

    The split is by whitespace-separated words with no overlap. That is a real
    engineering trade-off, not an accident: it keeps identifiers stable and
    ingestion repeatable, and it can place a phrase on both sides of a
    boundary. Task 2.8 inspects exactly that consequence.

    Each chunk copies the parent document's access label and provenance
    unchanged, so a retrieved chunk can always name its tenancy, its
    classification tier, and the custody record it came from.
    """
    if chunk_words < 1:
        raise ValueError("chunk_words must be at least 1")
    words = document.body.split()
    if not words:
        raise ValueError(f"document {document.document_id} has no body text")
    chunks: list[ChunkRecord] = []
    for index, offset in enumerate(range(0, len(words), chunk_words)):
        text = " ".join(words[offset : offset + chunk_words])
        chunks.append(
            ChunkRecord(
                chunk_id=f"{document.document_id}#{index:04d}",
                document_id=document.document_id,
                chunk_index=index,
                text=text,
                embedding=embed(f"{document.title} {text}"),
                access=document.access,
                provenance=document.provenance,
            )
        )
    return chunks
