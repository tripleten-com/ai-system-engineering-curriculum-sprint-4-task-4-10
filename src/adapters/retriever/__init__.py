"""Coldline.

===================

File:              src/adapters/retriever/__init__.py
Component:         Adapter — Retriever package exports
Purpose:           Re-export the supplied PostgreSQL hybrid retrieval adapter.
Interacts With:    Composition roots and the retrieval workflow
Sprint/Task:       Sprint 2 — Project 2
Concepts:          Boundary translation, deterministic infrastructure
Tools:             Python 3.12
"""

from adapters.retriever.postgres_hybrid import CANDIDATE_POOL, PostgresHybridRetriever

__all__ = ["CANDIDATE_POOL", "PostgresHybridRetriever"]
