"""Coldline.

===================

File:              src/api/idempotency.py
Component:         API — Idempotency handler
Purpose:           Apply the idempotency contract to one HTTP write handler.
Interacts With:    The idempotency store contract and the versioned API routers
Sprint/Task:       Sprint 2 — Project 2 / Task 2.5
Concepts:          Idempotent writes, replay, bounded scaffolding
Tools:             Python 3.12, FastAPI
"""

from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import HTTPException, Request, Response
from fastapi.encoders import jsonable_encoder
from opentelemetry import trace
from pydantic import BaseModel

from domain.idempotency import (
    ClaimState,
    IdempotencyConflict,
    IdempotencyStore,
    StoredResponse,
)

_TRACER = trace.get_tracer(__name__)

IDEMPOTENCY_HEADER = "Idempotency-Key"
MINIMUM_KEY_LENGTH = 8
MAXIMUM_KEY_LENGTH = 200


class IdempotencyHandler:
    """Wrap one write operation so a repeated request replays its response.

    This scaffold is supplied and protected. Task 2.5 asks a student to apply
    it to exactly one write path, not to build one.

    The sequence is fixed, and each step exists for a reason:

    1. Read and validate the `Idempotency-Key` header. A missing or malformed
       key is a client error, because guessing a key would defeat the point.
    2. Claim the key *before* performing the operation. A concurrent duplicate
       then finds the key in flight instead of performing the work twice.
    3. Perform the operation only when this caller won the claim.
    4. Record the response *after* the operation succeeds. A crash in between
       leaves the key claimed, not falsely completed.
    5. Release the claim when the operation fails, so a retry is possible.

    A replay returns the recorded status and body byte for byte. It does not
    re-run the operation, which is what makes the underlying write happen once.
    """

    def __init__(self, store: IdempotencyStore, *, operation_id: str) -> None:
        """Bind the handler to one store and one operation identity."""
        if not operation_id:
            raise ValueError("operation_id must not be empty")
        self._store = store
        self._operation_id = operation_id

    @property
    def operation_id(self) -> str:
        """Return the operation identity this handler protects."""
        return self._operation_id

    async def run(
        self,
        request: Request,
        response: Response,
        operation: Callable[[], Awaitable[tuple[int, BaseModel]]],
    ) -> Any:
        """Run one write operation at most once for a given idempotency key.

        ``operation`` returns the status code and the response model it would
        have produced without idempotency. The handler owns everything else.
        """
        key = _required_key(request)
        with _TRACER.start_as_current_span(
            "idempotency.run",
            attributes={"coldline.operation_id": self._operation_id},
        ):
            try:
                claim = await self._store.claim(key, self._operation_id)
            except IdempotencyConflict as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc

            if claim.state is ClaimState.COMPLETED:
                assert claim.response is not None
                response.status_code = claim.response.status_code
                response.headers["Idempotency-Replayed"] = "true"
                return _decoded(claim.response.body)

            if claim.state is ClaimState.IN_FLIGHT:
                # An identical request is still running. Answering 409 is
                # honest: the caller may retry, and neither answer invents a
                # result the first attempt has not produced yet.
                raise HTTPException(
                    status_code=409,
                    detail="an identical request with this idempotency key is still in flight",
                )

            try:
                status_code, payload = await operation()
            except HTTPException:
                await self._store.release(key, self._operation_id)
                raise
            except Exception:
                await self._store.release(key, self._operation_id)
                raise

            body = payload.model_dump_json()
            await self._store.complete(
                key, self._operation_id, StoredResponse(status_code=status_code, body=body)
            )
            response.status_code = status_code
            response.headers["Idempotency-Replayed"] = "false"
            return jsonable_encoder(payload)


def _required_key(request: Request) -> str:
    """Return the validated idempotency key or raise a client error."""
    key = request.headers.get(IDEMPOTENCY_HEADER, "").strip()
    if not key:
        raise HTTPException(
            status_code=400,
            detail=f"the {IDEMPOTENCY_HEADER} header is required for this operation",
        )
    if not MINIMUM_KEY_LENGTH <= len(key) <= MAXIMUM_KEY_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=(
                f"the {IDEMPOTENCY_HEADER} header must be between {MINIMUM_KEY_LENGTH} and "
                f"{MAXIMUM_KEY_LENGTH} characters"
            ),
        )
    return key


def _decoded(body: str) -> Any:
    """Return the stored response body as JSON-compatible data."""
    import json

    return json.loads(body)
