"""Coldline.

===================

File:              src/adapters/persistence/__init__.py
Component:         Persistence adapters — Package exports
Purpose:           Expose internal persistence adapters.
Interacts With:    Domain contracts, ports, and local providers
Sprint/Task:       Sprint 4 — Project 4
Concepts:          Boundary translation, deterministic infrastructure
Tools:             Python 3.12
"""

from adapters.persistence.audit_store import PostgresAuditStore
from adapters.persistence.corpus_loader import CorpusLoader, LoadReport
from adapters.persistence.document_repository import PostgresDocumentRepository
from adapters.persistence.idempotency import PostgresIdempotencyStore
from adapters.persistence.postgres import PostgresExceptionRepository

__all__ = [
    "CorpusLoader",
    "LoadReport",
    "PostgresAuditStore",
    "PostgresDocumentRepository",
    "PostgresExceptionRepository",
    "PostgresIdempotencyStore",
]
