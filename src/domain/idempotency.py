"""Coldline.

===================

File:              src/domain/idempotency.py
Component:         Domain — Idempotency contracts
Purpose:           Define the provider-neutral idempotency claim and replay contract.
Interacts With:    The idempotency store adapter and the API idempotency handler
Sprint/Task:       Sprint 2 — Project 2
Concepts:          Idempotent writes, replay, claim ownership
Tools:             Python 3.12, Pydantic
"""

from datetime import datetime
from enum import StrEnum
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field


class ClaimState(StrEnum):
    """Describe what a caller found when it claimed an idempotency key."""

    CLAIMED = "claimed"
    """This caller now owns the key and must perform the operation."""

    IN_FLIGHT = "in_flight"
    """Another caller owns the key and has not finished yet."""

    COMPLETED = "completed"
    """The operation already finished; its stored response is the answer."""


class StoredResponse(BaseModel):
    """Carry the response one completed operation produced."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    status_code: int = Field(ge=100, le=599)
    body: str


class IdempotencyClaim(BaseModel):
    """Report the outcome of one claim attempt."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    key: str = Field(min_length=1, max_length=200)
    operation_id: str = Field(min_length=1, max_length=120)
    state: ClaimState
    response: StoredResponse | None = None
    claimed_at: datetime | None = None


class IdempotencyConflict(RuntimeError):
    """Report that one key was reused for a different operation.

    A key identifies one attempt at one operation. Letting the same key stand
    for two different operations would make a replay return the wrong
    response, so this is refused rather than resolved.
    """


class IdempotencyStore(Protocol):
    """Claim keys and record the responses completed operations produced.

    This is an approved internal collaborator, not a sixth application port: it
    names no external resource and crosses no provider boundary.

    The contract is deliberately small, and the order matters. A caller claims
    *before* performing the operation, so a concurrent duplicate finds the key
    in flight rather than performing the work twice. It completes *after* the
    operation succeeds, so a crash mid-operation leaves the key claimed rather
    than falsely completed.
    """

    async def claim(self, key: str, operation_id: str) -> IdempotencyClaim:
        """Take ownership of one key, or report who already has it.

        Raises:
            IdempotencyConflict: the key exists for a different operation.

        """
        ...

    async def complete(self, key: str, operation_id: str, response: StoredResponse) -> None:
        """Record the response one completed operation produced."""
        ...

    async def release(self, key: str, operation_id: str) -> None:
        """Give up a claim so a later attempt can retry.

        Called when the operation failed. Keeping the claim would turn one
        transient failure into a permanently unusable key.
        """
        ...
