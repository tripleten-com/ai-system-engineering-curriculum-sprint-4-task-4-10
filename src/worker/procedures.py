"""Coldline.

===================

File:              src/worker/procedures.py
Component:         Worker — Procedure lookup
Purpose:           Retrieve the procedure excerpt the worker sends with each model request.
Interacts With:    The Retriever port, domain contracts, worker use cases
Sprint/Task:       Sprint 4 — Project 4
Concepts:          Retrieval-augmented request, fixed service scope, bounded excerpt
Tools:             Python 3.12

The worker asks the supplied hybrid retriever for the procedure that matches
one excursion, with one fixed service scope rather than a caller's identity:
the worker serves every shipment, so it reads every tier of the tenancy the
procedures live under. The top-ranked chunk becomes a bounded excerpt that
travels in the model request beside the reading and the handling note.
"""

import hashlib
import re
from dataclasses import dataclass

from domain.contracts import (
    AuthorizationContext,
    Candidate,
    RetrievalRequest,
    SensorReading,
)
from ports import Retriever

# Words of the top chunk carried into the model request.
EXCERPT_WORDS = 80
# A handling window a procedure states in digits, such as "within 30 minutes".
# Some procedures write it as an expression ("2*15 minutes"); the group keeps
# digits and arithmetic operators only.
_WINDOW = re.compile(r"(\d+(?:\s*[+\-*/]\s*\d+)*)\s*minutes?\b")


@dataclass(frozen=True)
class ProcedureExcerpt:
    """Carry the retrieved procedure, or the fact that nothing matched."""

    document_id: str | None
    chunk_id: str | None
    text: str
    window_minutes: float | None

    @property
    def found(self) -> bool:
        """Return whether retrieval produced a procedure for the reading."""
        return self.document_id is not None


class ProcedureLookup:
    """Find the procedure excerpt for one reading through the Retriever port."""

    def __init__(
        self,
        retriever: Retriever,
        *,
        scope: AuthorizationContext,
        top_k: int = 3,
        dense_weight: float = 0.5,
        excerpt_words: int = EXCERPT_WORDS,
    ) -> None:
        """Bind the lookup to the port, the service scope, and the excerpt bound."""
        if top_k < 1:
            raise ValueError("top_k must be at least 1")
        if excerpt_words < 1:
            raise ValueError("excerpt_words must be at least 1")
        self._retriever = retriever
        self._scope = scope
        self._top_k = top_k
        self._dense_weight = dense_weight
        self._excerpt_words = excerpt_words

    @property
    def scope(self) -> AuthorizationContext:
        """Return the fixed service scope every lookup runs under."""
        return self._scope

    async def find(self, reading: SensorReading) -> ProcedureExcerpt:
        """Return the bounded excerpt of the best-ranked procedure for the reading.

        Raises:
            RetrievalUnavailable: the retrieval backend could not answer.

        """
        query = query_for(reading)
        key = query_key(query)
        result = await self._retriever.search_hybrid(
            RetrievalRequest(
                query_id=f"procedure-{key[:12]}",
                text=query,
                authorization=self._scope,
                top_k=self._top_k,
                dense_weight=self._dense_weight,
            )
        )
        return excerpt_from(result.results, words=self._excerpt_words)


def query_for(reading: SensorReading) -> str:
    """Phrase one excursion as the question the corpus answers.

    Only the reading's shape goes into the query: which bound it crossed. The
    handling note is not part of the question, so what a dispatcher typed can
    change the model request but not which procedure is retrieved.
    """
    direction = "above" if reading.temperature_c > reading.allowed_max_c else "below"
    return (
        f"temperature reading {direction} the accepted handling range "
        "thermal excursion escalation containment"
    )


def query_key(query: str) -> str:
    """Return the short, stable key that names one query text in its query id."""
    return hashlib.md5(query.encode("utf-8")).hexdigest()


def excerpt_from(candidates: tuple[Candidate, ...], *, words: int) -> ProcedureExcerpt:
    """Turn the best-ranked candidate into a bounded excerpt, or an empty one."""
    if not candidates:
        return ProcedureExcerpt(
            document_id=None,
            chunk_id=None,
            text="",
            window_minutes=None,
        )
    best = min(candidates, key=lambda candidate: candidate.rank)
    text = " ".join(best.text.split()[:words])
    return ProcedureExcerpt(
        document_id=best.document_id,
        chunk_id=best.chunk_id,
        text=text,
        window_minutes=window_minutes(text),
    )


def window_minutes(text: str) -> float | None:
    """Return the handling window a procedure states in digits, if it states one.

    The supplied corpus writes its windows in words, so this is None for every
    supplied procedure; a procedure written with digits, or with a small
    arithmetic expression such as ``2*15 minutes``, gives its value here. The
    expression is read by a small parser over the digits and the four operators
    the pattern admits: ``*`` and ``/`` bind before ``+`` and ``-``, each level
    is read left to right, the numbers stay integers until the final conversion
    and ``/`` is true division, so the value is the one Python gives the same
    expression. A division by zero, or anything the parser cannot read as one
    expression, gives None.
    """
    match = _WINDOW.search(text)
    if match is None:
        return None
    tokens = re.findall(r"\d+|[+\-*/]", match.group(1))

    def term(position: int) -> tuple[int | float, int]:
        """Read one product of numbers from ``position``; return it and its end."""
        value: int | float = int(tokens[position])
        position += 1
        while position < len(tokens) and tokens[position] in ("*", "/"):
            operand = int(tokens[position + 1])
            if tokens[position] == "*":
                value = value * operand
            else:
                value = value / operand
            position += 2
        return value, position

    try:
        value, position = term(0)
        while position < len(tokens) and tokens[position] in ("+", "-"):
            operand, next_position = term(position + 1)
            if tokens[position] == "+":
                value = value + operand
            else:
                value = value - operand
            position = next_position
    except (IndexError, ValueError, ZeroDivisionError):
        return None
    if position != len(tokens):
        return None
    return float(value)
