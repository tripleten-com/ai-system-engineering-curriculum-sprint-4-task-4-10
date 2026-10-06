"""Coldline.

===================

File:              tests/doubles/__init__.py
Component:         Test doubles — Package exports
Purpose:           Re-export the supplied deterministic doubles for service-boundary tests.
Interacts With:    Contract tests and student tests
Sprint/Task:       Sprint 2 — Project 2
Concepts:          Independent execution, determinism
Tools:             Python 3.12
"""

from tests.doubles.retrieval import (
    AlternativeContextAssembler,
    AlternativeRetrievalOrchestrator,
    StubRetriever,
    candidate,
    stub_result,
)

__all__ = [
    "AlternativeContextAssembler",
    "AlternativeRetrievalOrchestrator",
    "StubRetriever",
    "candidate",
    "stub_result",
]
