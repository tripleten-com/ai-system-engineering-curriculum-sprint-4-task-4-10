"""Coldline.

===================

File:              src/api/access_policy.py
Component:         API — Protected authorization composition
Purpose:           Supply the dimension complementary to one student mechanism.
Interacts With:    AccessConstraintProvider and the hybrid retrieval adapter
Sprint/Task:       Sprint 2 — Project 2
Concepts:          Query-time authorization, intersection, composition
Tools:             Python 3.12
"""

from domain.access import AccessConstraint, AccessConstraintProvider
from domain.contracts import AccessTier, AuthorizationContext


class ComposedAccessConstraints:
    """Preserve the selected mechanism and supply only its complement.

    The explicit choice is application wiring, never an answer-sheet read.
    This helper cannot correct a missing or incorrect selected dimension.
    None remains unrestricted and an empty tuple remains deny-all.
    """

    def __init__(self, selected: AccessConstraintProvider, *, selected_filter_type: str) -> None:
        """Reject an unknown choice before the application starts."""
        if selected_filter_type not in {"tenant_boundary", "role_classification"}:
            raise ValueError("select tenant_boundary or role_classification explicitly")
        self.selected = selected
        self.selected_filter_type = selected_filter_type

    def constrain(self, authorization: AuthorizationContext) -> AccessConstraint:
        """Intersect the student's predicate with the complementary constraint."""
        constraint = self.selected.constrain(authorization)
        if self.selected_filter_type == "tenant_boundary":
            tiers = (
                (AccessTier.STANDARD, AccessTier.RESTRICTED)
                if authorization.clearance is AccessTier.RESTRICTED
                else (AccessTier.STANDARD,)
            )
            return AccessConstraint(
                tenant_ids=constraint.tenant_ids,
                access_tiers=tuple(
                    tier
                    for tier in tiers
                    if constraint.access_tiers is None or tier in constraint.access_tiers
                ),
            )
        return AccessConstraint(
            tenant_ids=tuple(
                tenant
                for tenant in (authorization.tenant_id,)
                if constraint.tenant_ids is None or tenant in constraint.tenant_ids
            ),
            access_tiers=constraint.access_tiers,
        )
