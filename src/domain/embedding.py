"""Coldline.

===================

File:              src/domain/embedding.py
Component:         Domain — Deterministic embedding
Purpose:           Turn text into a repeatable dense vector without a model service.
Interacts With:    Corpus ingestion, the hybrid retrieval adapter, and the benchmark harness
Sprint/Task:       Sprint 2 — Project 2
Concepts:          Determinism, dense representation, local fidelity
Tools:             Python 3.12, hashlib
"""

import re
from hashlib import blake2b
from math import sqrt

EMBEDDING_DIMENSIONS = 64
_TOKEN = re.compile(r"[a-z0-9]+")


def tokenize(text: str) -> list[str]:
    """Return the lowercase alphanumeric tokens used by both search arms."""
    return _TOKEN.findall(text.casefold())


def embed(text: str) -> tuple[float, ...]:
    """Return a unit-length hashed bag-of-tokens vector for one text.

    This is a controlled algorithmic stand-in for a hosted embedding model, not
    a semantic model. It is used because it needs no network call, no paid
    provider, and no GPU, and because the same text always produces the same
    vector in every process and on every platform. ``blake2b`` is used instead
    of ``hash()`` precisely because CPython randomizes string hashing per
    process, which would make ingestion and querying disagree.

    Similarity is therefore token-overlap similarity in a projected space. It
    does not capture paraphrase, synonymy, or word order, and no claim about
    production semantic retrieval quality follows from it. See
    ``docs/fidelity/Retriever.md``.
    """
    vector = [0.0] * EMBEDDING_DIMENSIONS
    for token in tokenize(text):
        digest = blake2b(token.encode("utf-8"), digest_size=8).digest()
        bucket = int.from_bytes(digest[:4], "big") % EMBEDDING_DIMENSIONS
        # The sign spreads unrelated tokens apart instead of letting every
        # token push the same bucket in one direction.
        sign = 1.0 if digest[4] % 2 == 0 else -1.0
        vector[bucket] += sign
    norm = sqrt(sum(value * value for value in vector))
    if norm == 0.0:
        # An empty or symbol-only query has no direction; return the zero
        # vector rather than inventing one, and let the caller rank on the
        # sparse arm alone.
        return tuple(vector)
    return tuple(value / norm for value in vector)


def format_vector(vector: tuple[float, ...]) -> str:
    """Return the textual ``vector`` literal PostgreSQL parameter binding expects."""
    return "[" + ",".join(f"{value:.9f}" for value in vector) + "]"
