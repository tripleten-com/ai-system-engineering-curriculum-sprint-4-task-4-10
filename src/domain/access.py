"""Coldline.

===================

File:              src/domain/access.py
Component:         Domain — Access constraints
Purpose:           Define the provider-neutral access predicate applied inside retrieval queries.
Interacts With:    The hybrid retrieval adapter and the Task 2.4 student extension
Sprint/Task:       Sprint 2 — Project 2
Concepts:          Authorization boundary, declarative predicate, dependency inversion
Tools:             Python 3.12, Pydantic
"""

from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, model_validator

from domain.contracts import AccessTier, AuthorizationContext


class AccessConstraint(BaseModel):
    """Declare which tenancies and classification tiers a query may read.

    This is a *declarative* predicate, not SQL. The supplied retrieval adapter
    translates it into parameterized constraints inside both the dense and the
    sparse query, which is why an implementation cannot accidentally turn into
    a post-retrieval filter or a string-formatted query.

    Three states are deliberately distinguishable:

    | Value | Meaning |
    |---|---|
    | ``AccessConstraint()`` | no restriction — every stored chunk is readable |
    | ``AccessConstraint(tenant_ids=("t-a",))`` | only that tenancy is readable |
    | ``AccessConstraint(tenant_ids=())`` | nothing is readable |

    The empty tuple is a real value rather than an error so that a filter which
    denies everything is *observable* instead of silently equivalent to "no
    filter". Curriculum verification uses that distinction: a constraint that
    denies everything must fail the permitted-retrieval check.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    tenant_ids: tuple[str, ...] | None = None
    access_tiers: tuple[AccessTier, ...] | None = None

    @model_validator(mode="after")
    def validate_values(self) -> "AccessConstraint":
        """Reject blank tenancy values that would produce an unusable constraint."""
        if self.tenant_ids is not None and any(
            not value or value != value.strip() for value in self.tenant_ids
        ):
            raise ValueError("tenant_ids entries must be non-blank and untrimmed of padding")
        return self

    @property
    def restricts(self) -> bool:
        """Return whether this constraint removes anything at all."""
        return self.tenant_ids is not None or self.access_tiers is not None

    @property
    def denies_everything(self) -> bool:
        """Return whether this constraint can never admit a stored chunk."""
        return self.tenant_ids == () or self.access_tiers == ()


@runtime_checkable
class AccessConstraintProvider(Protocol):
    """Turn one caller's authorization context into a query-time constraint.

    This is an approved internal collaborator, not a sixth application port: it
    crosses no provider boundary and names no external resource.
    """

    def constrain(self, authorization: AuthorizationContext) -> AccessConstraint:
        """Return the constraint that applies to one caller."""
        ...


class UnrestrictedAccessConstraints:
    """Apply no access constraint at all.

    This is the supplied Task 2.1 behavior and it is deliberately explicit. The
    corpus carries tenancy and classification labels from ingestion onward, and
    the retrieval request already carries the caller's context, but *nothing is
    enforced yet*: every stored chunk is readable by every caller.
    ``RetrievalResult.authorization_enforced`` reports ``False`` while this
    provider is composed, and the authorization stage records that it dropped
    no candidates. Task 2.4 replaces this provider with an enforcing one.

    The adapter derives ``authorization_enforced`` from the constraint it
    actually applied, never from a provider's own claim about itself, so a
    provider cannot report enforcement it does not perform.
    """

    def constrain(self, authorization: AuthorizationContext) -> AccessConstraint:
        """Return an unrestricted constraint regardless of the caller."""
        return AccessConstraint()
