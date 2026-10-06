"""Coldline.

===================
File:              tests/unit/test_access_policy.py
Component:         Tests — Authorization composition
Purpose:           Verify complementary protection without repairing student logic.
Interacts With:    Protected composition helper and retrieval constraints
Sprint/Task:       Sprint 2 — Project 2
Concepts:          Authorization, unrestricted versus deny-all, query-time filtering
Tools:             Python 3.12, pytest
"""

import pytest

from api.access_policy import ComposedAccessConstraints
from domain.access import AccessConstraint
from domain.contracts import AccessTier, AuthorizationContext


class FixedConstraints:
    """Return a deliberate good or bad selected predicate unchanged."""

    def __init__(self, constraint: AccessConstraint) -> None:
        """Store one observable constraint."""
        self.constraint = constraint

    def constrain(self, authorization: AuthorizationContext) -> AccessConstraint:
        """Ignore context to model mistakes that composition must not fix."""
        return self.constraint


@pytest.mark.parametrize("choice", ["", "both", "TENANT_BOUNDARY", None])
def test_composition_rejects_an_invalid_choice(choice: str) -> None:
    """An unknown mechanism must fail at construction."""
    with pytest.raises(ValueError, match="explicitly"):
        ComposedAccessConstraints(FixedConstraints(AccessConstraint()), selected_filter_type=choice)


@pytest.mark.parametrize("choice", ["tenant_boundary", "role_classification"])
@pytest.mark.parametrize("selected", [None, (), ("wrong",)])
def test_helper_does_not_repair_the_selected_dimension(choice: str, selected: tuple | None) -> None:
    """Missing, deny-all, and incorrect selected restrictions survive composition."""
    constraint = (
        AccessConstraint(tenant_ids=selected)
        if choice == "tenant_boundary"
        else AccessConstraint(
            access_tiers=None
            if selected is None
            else (() if selected == () else (AccessTier.RESTRICTED,))
        )
    )

    result = ComposedAccessConstraints(
        FixedConstraints(constraint), selected_filter_type=choice
    ).constrain(AuthorizationContext(tenant_id="tenant-a", clearance=AccessTier.STANDARD))

    if choice == "tenant_boundary":
        assert result.tenant_ids == constraint.tenant_ids

        assert result.access_tiers == (AccessTier.STANDARD,)

    else:
        assert result.access_tiers == constraint.access_tiers

        assert result.tenant_ids == ("tenant-a",)

    if selected == ():
        assert result.denies_everything


@pytest.mark.parametrize("choice", ["tenant_boundary", "role_classification"])
def test_complement_intersection_preserves_explicit_deny_all(choice: str) -> None:
    """An empty unselected dimension must not become unrestricted."""
    result = ComposedAccessConstraints(
        FixedConstraints(AccessConstraint(tenant_ids=(), access_tiers=())),
        selected_filter_type=choice,
    ).constrain(AuthorizationContext(tenant_id="tenant-a", clearance=AccessTier.RESTRICTED))

    assert result.tenant_ids == ()

    assert result.access_tiers == ()


@pytest.mark.parametrize("choice", ["tenant_boundary", "role_classification"])
@pytest.mark.parametrize("clearance", [AccessTier.STANDARD, AccessTier.RESTRICTED])
def test_correct_selected_policy_composes_both_protections(
    choice: str, clearance: AccessTier
) -> None:
    """Each valid student mechanism produces the same complete application policy."""
    tiers = (
        (AccessTier.STANDARD, AccessTier.RESTRICTED)
        if clearance is AccessTier.RESTRICTED
        else (AccessTier.STANDARD,)
    )

    selected = (
        AccessConstraint(tenant_ids=("tenant-a",))
        if choice == "tenant_boundary"
        else AccessConstraint(access_tiers=tiers)
    )

    result = ComposedAccessConstraints(
        FixedConstraints(selected), selected_filter_type=choice
    ).constrain(AuthorizationContext(tenant_id="tenant-a", clearance=clearance))

    assert result == AccessConstraint(tenant_ids=("tenant-a",), access_tiers=tiers)
