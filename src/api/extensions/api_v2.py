"""Coldline.

===================

File:              src/api/extensions/api_v2.py
Component:         API — Version 2 router
Purpose:           Add one versioned write endpoint and protect its write path.
Interacts With:    api/v2_contracts.py, api/idempotency.py, the wiring factory
Sprint/Task:       Sprint 2 — Project 2
Concepts:          API versioning, idempotent writes
Tools:             Python 3.12, FastAPI

This is the reference version 2 endpoint from Task 2.5, now supplied and
protected. A student's own Task 2.5 implementation - of either supported
operation - stays in that Task's pull request and never has to match this
file.
"""

from typing import Any

from fastapi import APIRouter, Request, Response, status

from api.document_service import DocumentService
from api.idempotency import IdempotencyHandler
from api.v2_contracts import (
    DOCUMENTS_OPERATION_ID,
    DOCUMENTS_V2_PATH,
    DocumentV2Request,
    DocumentV2Response,
)
from domain.idempotency import IdempotencyStore


def build_documents_v2_router(documents: DocumentService, store: IdempotencyStore) -> APIRouter:
    """Return the version 2 document router with its write path protected.

    Version 1 is untouched. This is an addition: a v1 caller keeps its own
    route, its own response shape, and its freedom to send no idempotency key.

    The write itself lives inside ``operation``, and the handler decides
    whether to call it. On a replay the handler returns the stored response and
    never calls it at all, which is what makes the underlying write happen
    exactly once per key.
    """
    router = APIRouter(tags=["v2"])
    handler = IdempotencyHandler(store, operation_id=DOCUMENTS_OPERATION_ID)

    @router.post(
        DOCUMENTS_V2_PATH,
        response_model=DocumentV2Response,
        status_code=status.HTTP_201_CREATED,
    )
    async def create_document_v2(
        payload: DocumentV2Request, request: Request, response: Response
    ) -> Any:
        """Persist one document and its chunks at most once per idempotency key."""

        async def operation() -> tuple[int, DocumentV2Response]:
            chunks = await documents.create(payload.document)
            return status.HTTP_201_CREATED, DocumentV2Response(
                document_id=payload.document.document_id,
                chunk_count=len(chunks),
                source_system=payload.source_system,
            )

        return await handler.run(request, response, operation)

    return router
