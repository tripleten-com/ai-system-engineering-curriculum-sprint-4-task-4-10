"""Coldline.

===================

File:              src/ports/retriever.py
Component:         Port — Retriever
Purpose:           Define the provider-neutral hybrid retrieval port.
Interacts With:    The retrieval workflow and the supplied PostgreSQL adapter
Sprint/Task:       Sprint 2 — Project 2
Concepts:          Dependency inversion, provider-neutral interface, stage evidence
Tools:             Python 3.12
"""

from typing import Protocol, runtime_checkable

from domain.contracts import RetrievalRequest, RetrievalResult


@runtime_checkable
class Retriever(Protocol):
    """Retrieve ranked context chunks for one authorized request.

    Sprint 1 shipped this port with no adapter and no caller: it was visible
    but inactive, and its single ``search(query) -> list[str]`` operation was
    never implemented or invoked. Sprint 2 activates the port, and activation
    is the point at which its operation is fixed. A bare query string cannot
    carry the caller's tenancy, the controlled retrieval parameters, or the
    per-stage evidence a diagnosis needs, so the activated contract is
    ``search_hybrid``. Nothing depended on the earlier shape.

    The contract is stable for the rest of Sprint 2. Task 2.4 changes retrieval
    *behavior* behind this signature; it does not change the signature.
    """

    async def search_hybrid(self, request: RetrievalRequest) -> RetrievalResult:
        """Return ranked chunks for one request together with stage evidence.

        The request carries the caller's authorization context and both
        controlled parameters (``top_k`` and ``dense_weight``). The result
        carries the final ranking and one ``StageEvidence`` entry per stage.

        Whether the authorization context is *enforced* is reported by
        ``RetrievalResult.authorization_enforced``, which an implementation
        derives from the constraint it actually applied rather than asserting
        about itself.

        Raises:
            RetrievalUnavailable: the retrieval backend could not answer.

        """
        ...
