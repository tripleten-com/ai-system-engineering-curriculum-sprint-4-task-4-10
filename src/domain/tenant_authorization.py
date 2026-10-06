"""Coldline.

===================

File:              src/domain/tenant_authorization.py
Component:         Domain — Tenant-boundary authorization
Purpose:           Restrict every retrieval query to the caller's own tenancy.
Interacts With:    domain/access.py and the supplied hybrid retrieval adapter
Sprint/Task:       Sprint 2 — Project 2
Concepts:          Query-time authorization, declarative predicates
Tools:             Python 3.12

This is the reference authorization mechanism from Task 2.4, now supplied and
protected. Task 2.4 offered two mechanisms; the tenant boundary is the
documented reference so every later Task starts from one deterministic policy.
A student's own Task 2.4 implementation stays in that Task's pull request and is
never required to match this file.

It lives in `domain` because it depends on nothing outward: it maps one
authorization context to one declarative constraint and names no external
resource.
"""

from domain.access import AccessConstraint
from domain.contracts import AuthorizationContext


class TenantBoundaryAccessConstraints:
    """Restrict every retrieval query to the caller's own tenancy.

    Implements ``domain.access.AccessConstraintProvider``.

    This supplies the tenant dimension. The protected composition helper supplies
    classification, so the later application enforces both dimensions.
    """

    def constrain(self, authorization: AuthorizationContext) -> AccessConstraint:
        """Return the constraint for one caller."""
        return AccessConstraint(tenant_ids=(authorization.tenant_id,))
