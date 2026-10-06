"""Coldline.

===================

File:              src/domain/fusion.py
Component:         Domain — Candidate fusion
Purpose:           Merge dense and sparse candidate rankings into one ordered list.
Interacts With:    The hybrid retrieval adapter and the retrieval workflow
Sprint/Task:       Sprint 2 — Project 2
Concepts:          Rank aggregation, determinism, controlled parameters
Tools:             Python 3.12
"""

from collections.abc import Sequence

from domain.contracts import Candidate

RANK_CONSTANT = 60


def fuse(
    dense: Sequence[Candidate],
    sparse: Sequence[Candidate],
    *,
    dense_weight: float,
    limit: int,
) -> list[Candidate]:
    """Return weighted reciprocal-rank fusion of two candidate lists.

    Each arm contributes ``weight / (RANK_CONSTANT + rank)`` for the chunks it
    returned and nothing for the chunks it did not. Reciprocal rank is used
    rather than raw scores because a cosine distance and a text-search rank are
    not on a comparable scale, so adding them directly would let one arm's
    units dominate the other.

    ``dense_weight`` is the single supplied fusion weight; the sparse arm
    receives ``1 - dense_weight``. Ties break on ``chunk_id`` so the same two
    inputs always produce the same order.
    """
    if not 0.0 <= dense_weight <= 1.0:
        raise ValueError("dense_weight must be between 0.0 and 1.0")
    if limit < 1:
        raise ValueError("limit must be at least 1")
    sparse_weight = 1.0 - dense_weight
    scores: dict[str, float] = {}
    seen: dict[str, Candidate] = {}
    for arm, weight in ((dense, dense_weight), (sparse, sparse_weight)):
        for candidate in arm:
            seen.setdefault(candidate.chunk_id, candidate)
            scores[candidate.chunk_id] = scores.get(candidate.chunk_id, 0.0) + weight / (
                RANK_CONSTANT + candidate.rank
            )
    ordered = sorted(scores.items(), key=lambda item: (-item[1], item[0]))
    return [
        seen[chunk_id].model_copy(update={"rank": position, "score": round(score, 12)})
        for position, (chunk_id, score) in enumerate(ordered[:limit], start=1)
    ]
