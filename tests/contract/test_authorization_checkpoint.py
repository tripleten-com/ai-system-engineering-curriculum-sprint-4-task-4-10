"""Coldline.

===================

File:              tests/contract/test_authorization_checkpoint.py
Component:         Contract tests — Authorization extension
Purpose:           Verify query-time authorization behind the published Retriever contract.
Interacts With:    The composed constraint provider and the running retrieval API
Sprint/Task:       Sprint 2 — Project 2 / Task 2.5 onward
Concepts:          Scope exclusion, permitted retrieval, published port stability
Tools:             Python 3.12, pytest, httpx
"""

import inspect

import httpx
import pytest

import ports
from api.extensions import wiring
from domain.access import AccessConstraint
from domain.contracts import AccessTier, AuthorizationContext
from tests.runtime_config import host_port

# The supplied completed checkpoint must retain both protections in later Tasks.
pytestmark = [pytest.mark.runtime]

# Corpus facts these checks rely on. Each is a supplied fixture, not a student
# artefact, and each is used because it isolates exactly one dimension.
OWN_TENANT = "tenant-northwind"
OWN_STANDARD_QUERY = "container pre-cool fault before loading"
OWN_STANDARD_DOCUMENT = "sop-precool-container"
FOREIGN_TENANT = "tenant-coldline-ops"
FOREIGN_QUERY = "hazardous material spill evacuate transfer bay"
FOREIGN_DOCUMENT = "rule-hazmat-spill"
OWN_RESTRICTED_QUERY = "escorted pharmaceutical movements two named custodians"
OWN_RESTRICTED_DOCUMENT = "rule-pharma-escort"


def _api() -> str:
    """Return the API base URL, honoring the documented host-port override."""
    return f"http://localhost:{host_port('COLDLINE_API_HOST_PORT', 8000)}"


def _constrain(tenant_id: str, clearance: AccessTier) -> AccessConstraint:
    """Ask the composed provider for one caller's constraint."""
    provider = wiring.build_access_constraints()
    return provider.constrain(AuthorizationContext(tenant_id=tenant_id, clearance=clearance))


def _search(text: str, tenant_id: str, clearance: str) -> dict[str, object]:
    """Run one retrieval request against the running API."""
    with httpx.Client(timeout=30.0) as client:
        try:
            response = client.post(
                f"{_api()}/api/v1/retrieval/search",
                json={
                    "query_id": "q-authorization-check",
                    "text": text,
                    "authorization": {"tenant_id": tenant_id, "clearance": clearance},
                    "explain": True,
                },
            )
        except httpx.HTTPError as exc:
            pytest.fail(f"could not reach the retrieval API at {_api()}: {exc}")
    assert response.status_code == 200, response.text
    payload: dict[str, object] = response.json()
    return payload


def _every_identifier(payload: dict[str, object]) -> set[str]:
    """Return every chunk identifier the response mentions, at any stage.

    Checking the final results alone would accept an implementation that read
    out-of-scope rows and dropped them afterwards. The stage evidence is what
    shows whether those rows were ever fetched.
    """
    identifiers: set[str] = set()
    results = payload["results"]
    assert isinstance(results, list)
    identifiers.update(str(item["chunk_id"]) for item in results)
    stages = payload["stages"]
    assert isinstance(stages, list)
    for stage in stages:
        for key in ("admitted", "dropped"):
            identifiers.update(str(value) for value in stage.get(key, []))
    return identifiers


def test_the_composed_policy_actually_restricts_something() -> None:
    """The supplied completed checkpoint must retain an enforcing policy."""
    constraint = _constrain(OWN_TENANT, AccessTier.STANDARD)
    assert constraint.restricts, (
        "the supplied completed checkpoint lost its authorization constraint; inspect "
        "build_access_constraints in src/api/extensions/wiring.py"
    )
    assert not constraint.denies_everything, (
        "the composed policy denies everything, which excludes the caller's own content too"
    )


def test_permitted_retrieval_still_returns_the_callers_own_content() -> None:
    """A filter that excludes everything is not an authorization filter."""
    payload = _search(OWN_STANDARD_QUERY, OWN_TENANT, "standard")
    results = payload["results"]
    assert isinstance(results, list)
    assert results, (
        "an authorized query returned nothing at all. A constraint that denies everything "
        "excludes out-of-scope content and the caller's own content alike, and does not pass."
    )
    documents = {str(item["document_id"]) for item in results}
    assert OWN_STANDARD_DOCUMENT in documents, (
        f"the caller's own document {OWN_STANDARD_DOCUMENT!r} was not returned; found "
        f"{sorted(documents)}"
    )
    assert payload["authorization_enforced"] is True, (
        "the response reports that no constraint was applied"
    )


@pytest.mark.parametrize(
    ("text", "excluded_document"),
    [(FOREIGN_QUERY, FOREIGN_DOCUMENT), (OWN_RESTRICTED_QUERY, OWN_RESTRICTED_DOCUMENT)],
    ids=["foreign-tenant", "restricted-tier"],
)
def test_out_of_scope_content_is_never_fetched(text: str, excluded_document: str) -> None:
    """Both dimensions must exclude content from every pipeline stage."""
    payload = _search(text, OWN_TENANT, "standard")
    identifiers = _every_identifier(payload)
    leaked = sorted(
        identifier for identifier in identifiers if identifier.startswith(f"{excluded_document}#")
    )
    assert leaked == [], (
        f"{len(leaked)} out-of-scope chunk(s) of {excluded_document!r} reached the pipeline: "
        f"{leaked}. Filtering must happen inside both query arms, not after them."
    )


@pytest.mark.parametrize(
    ("text", "tenant", "expected"),
    [
        (FOREIGN_QUERY, FOREIGN_TENANT, FOREIGN_DOCUMENT),
        (OWN_RESTRICTED_QUERY, OWN_TENANT, OWN_RESTRICTED_DOCUMENT),
    ],
    ids=["foreign-owner", "cleared-owner"],
)
def test_a_cleared_caller_still_reaches_its_restricted_content(
    text: str, tenant: str, expected: str
) -> None:
    """Both dimensions retain content for its authorized caller."""
    payload = _search(text, tenant, "restricted")

    results = payload["results"]
    assert isinstance(results, list)
    documents = {str(item["document_id"]) for item in results}
    assert expected in documents, (
        f"the authorized caller could not reach {expected!r}; found {sorted(documents)}"
    )


@pytest.mark.parametrize("tenant", [OWN_TENANT, FOREIGN_TENANT, "tenant-new"])
@pytest.mark.parametrize("clearance", [AccessTier.STANDARD, AccessTier.RESTRICTED])
def test_composed_policy_enforces_both_dimensions(tenant: str, clearance: AccessTier) -> None:
    """The actual application composition must protect every caller on both axes."""
    constraint = _constrain(tenant, clearance)
    assert constraint.tenant_ids == (tenant,)
    expected = (
        {AccessTier.STANDARD, AccessTier.RESTRICTED}
        if clearance is AccessTier.RESTRICTED
        else {AccessTier.STANDARD}
    )
    assert constraint.access_tiers is not None
    assert set(constraint.access_tiers) == expected


def test_the_published_retriever_contract_is_unchanged() -> None:
    """The extension changes behavior behind the port, not the port itself."""
    operations = {
        name
        for name, _ in inspect.getmembers(ports.Retriever, inspect.isfunction)
        if not name.startswith("_")
    }
    assert operations == {"search_hybrid"}, (
        f"the published Retriever contract changed: {sorted(operations)}"
    )
    signature = inspect.signature(ports.Retriever.search_hybrid)
    assert list(signature.parameters) == ["self", "request"]
