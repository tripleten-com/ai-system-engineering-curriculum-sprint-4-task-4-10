"""Coldline.

===================

File:              src/api/extensions/wiring.py
Component:         API — Settled service wiring
Purpose:           Compose the application from the settled reference services.
Interacts With:    api/bootstrap.py, the document repository, domain services
Sprint/Task:       Sprint 2 — Project 2
Concepts:          Composition, dependency injection, bounded student surface
Tools:             Python 3.12, PostgreSQL

Every extension point in this package is now settled, so this file is supplied
and protected rather than student-editable. It is kept as the one place that
names which implementation the application composes, because that is what made
each earlier substitution a visible one-line change.

- Task 2.2's service boundary: `build_retrieval_orchestrator` returns the
  reference orchestration service supplied at `src/api/retrieval_orchestration.py`.
- Task 2.3's data layer: `build_document_repository` returns the reference
  repository.
- Task 2.4's authorization mechanism: `build_access_constraints` returns the
  reference combined tenancy-and-classification policy.
- Task 2.5's versioned write: `build_v2_router` returns the reference version 2
  document router.

Task 2.6 changes the database schema rather than the composition. Your work is
one generated revision under `migrations/versions/`.
"""

import asyncpg
from fastapi import APIRouter

from adapters.persistence.document_repository import PostgresDocumentRepository
from api.access_policy import ComposedAccessConstraints
from api.document_service import DocumentService
from api.extensions.api_v2 import build_documents_v2_router
from api.retrieval_orchestration import RetrievalOrchestrationService
from api.use_cases import ReadingApplication
from domain.access import AccessConstraintProvider
from domain.idempotency import IdempotencyStore
from domain.repositories import DocumentRepository
from domain.services import RetrievalOrchestrator
from domain.tenant_authorization import TenantBoundaryAccessConstraints
from ports import Retriever


def build_retrieval_orchestrator(
    retriever: Retriever,
    *,
    top_k: int,
    dense_weight: float,
    citation_limit: int,
) -> RetrievalOrchestrator:
    """Return the supplied reference retrieval-orchestration service."""
    return RetrievalOrchestrationService(
        retriever,
        top_k=top_k,
        dense_weight=dense_weight,
        citation_limit=citation_limit,
    )


def build_document_repository(pool: asyncpg.Pool) -> DocumentRepository | None:
    """Return the supplied reference document repository."""
    return PostgresDocumentRepository(pool)


def build_access_constraints() -> AccessConstraintProvider:
    """Return the access-constraint policy the retrieval adapter applies.

    The adapter applies this inside both query arms, so the constraint decides
    what is *fetched* rather than what is discarded afterwards.
    """
    return ComposedAccessConstraints(
        TenantBoundaryAccessConstraints(), selected_filter_type="tenant_boundary"
    )


def build_v2_router(
    *,
    documents: DocumentService,
    readings: ReadingApplication,
    store: IdempotencyStore,
) -> APIRouter | None:
    """Return the supplied reference version 2 document router.

    The composition root mounts whatever this returns. Both collaborators and
    the idempotency store are handed over already composed, so the router
    creates no pool, no client, and no second store.
    """
    return build_documents_v2_router(documents, store)
