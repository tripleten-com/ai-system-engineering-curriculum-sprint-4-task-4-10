"""Coldline.

===================

File:              tests/contract/test_authorization_diagnosis.py
Component:         Contract tests — Authorization diagnosis boundary
Purpose:           Check that a correct access denial is never reported as a defect.
Interacts With:    The diagnostic, the attribution rule, and the running retrieval API
Sprint/Task:       Sprint 2 — Project 2 / Task 2.8
Concepts:          Correct denial, custody evidence, controlled diagnostic case
Tools:             Python 3.12, pytest, httpx

Assesses nothing. It checks the property the designated investigation depends
on: that the published rule tells a *mislabelled* denial apart from a correct
one, using evidence a reader can re-derive from the committed fixtures.

Without this, the rule's first question would be untested in the one direction
that matters. An ordered stage rule that blames `authorization_filtering` for
every drop reads plausibly and is wrong: an access boundary withholding another
tenancy's content is the boundary working, and calling that a defect would
teach students to file the system's correct behavior as a fault.

So the supplied corpus carries both cases, and both are exercised here.
"""

from __future__ import annotations

import httpx
import pytest

from tests.diagnostics.attribution import (
    AUTHORIZATION_FILTERING,
    NO_DEFECT,
    STAGES,
    ChunkFacts,
    CustodyFacts,
    StageObservation,
    attribute,
    custody_facts,
    ruled_out,
)
from tests.diagnostics.inspect import (
    DOCUMENTS_PATH,
    PROVENANCE_PATH,
    Investigation,
    _json_lines,
    _tenant_id,
    custody_for,
    designated_investigation,
    facts_for,
    load_investigations,
    observe,
    search,
)

Evidence = tuple[StageObservation, ChunkFacts, CustodyFacts]

pytestmark = pytest.mark.runtime


def _evidence(investigation: Investigation) -> Evidence:
    """Run one investigation and return its three kinds of evidence."""
    with httpx.Client(timeout=30.0) as client:
        payload = search(client, investigation)
    return observe(investigation, payload), facts_for(investigation), custody_for(investigation)


def _contrast() -> Investigation:
    """Return the supplied contrast case: a denial that is correct."""
    contrast = [item for item in load_investigations() if not item.expected_readable]
    if not contrast:
        pytest.fail(
            "investigation.jsonl supplies no case with expected_readable false, so nothing "
            "here demonstrates that a correct denial is not a defect"
        )
    return contrast[0]


def test_the_designated_case_and_the_contrast_case_are_both_supplied() -> None:
    """One defect and one correct denial, or the comparison teaches nothing."""
    investigations = load_investigations()
    assert len(investigations) >= 2, (
        "the corpus supplies fewer than two investigations, so the lesson cannot show a "
        "mislabelled denial beside a correct one"
    )
    assert designated_investigation().expected_readable, (
        "the designated investigation is not expected to be readable, so it is not a defect "
        "and cannot be the graded case"
    )
    assert not _contrast().expected_readable


def test_the_designated_miss_is_attributed_to_the_access_boundary() -> None:
    """The controlled case must isolate the stage it was built to isolate.

    This is the authoring qualification for the case itself, kept in the
    repository so it runs on every checkout rather than living in a one-off
    report. It asserts the rule's conclusion, not a submission.
    """
    observation, facts, custody = _evidence(designated_investigation())

    assert not observation.readable
    assert custody.contradicts_label
    assert attribute(observation, facts, custody) == AUTHORIZATION_FILTERING


def test_a_correct_denial_is_not_attributed_to_any_stage() -> None:
    """The contrast case must come back as no defect at all.

    The caller is denied content that belongs to another tenancy and whose
    custody record agrees with that label. Every stage downstream is
    unobserved, and the rule must decline to name one rather than blame the
    boundary for enforcing itself.
    """
    investigation = _contrast()
    observation, facts, custody = _evidence(investigation)

    assert not observation.readable, (
        f"{investigation.target_chunk_id} is readable by a caller from another tenancy, so "
        "the access boundary is not enforcing what this contrast case assumes"
    )
    assert not custody.contradicts_label, (
        f"{custody.document_id} carries a label its custody record contradicts, so it is a "
        "mislabel rather than the correct-denial contrast this case is for"
    )
    verdict = attribute(observation, facts, custody)
    assert verdict == NO_DEFECT, (
        f"the published rule attributes this correct denial to {verdict!r}. A boundary that "
        "withholds another tenancy's content is working, and reporting that as a defect "
        "would teach a student to file correct behavior as a fault."
    )
    assert verdict not in STAGES


def test_a_correct_denial_exonerates_the_access_boundary() -> None:
    """A stage that correctly applied a correct label is proven, not unobserved.

    The general rule is that absence of evidence never exonerates a stage. This
    is the one case where the evidence is present rather than absent: the stage
    acted, and what it acted on is demonstrably labelled right.
    """
    observation, facts, custody = _evidence(_contrast())

    assert AUTHORIZATION_FILTERING in ruled_out(observation, facts, custody)


def test_the_designated_case_does_not_exonerate_the_access_boundary() -> None:
    """The cause of a miss can never also be ruled out."""
    observation, facts, custody = _evidence(designated_investigation())

    assert AUTHORIZATION_FILTERING not in ruled_out(observation, facts, custody)


def test_every_custodian_in_the_corpus_maps_to_one_tenancy_but_one() -> None:
    """The custody evidence only reads as evidence if the corpus is otherwise clean.

    The designated mislabel is identifiable because every *other* document
    agrees with its custodian. A second inconsistency would make the comparison
    ambiguous, and a corpus with none would leave the designated case with no
    evidence at all.
    """
    labels = {
        str(record["document_id"]): _tenant_id(record["access"])
        for record in _json_lines(DOCUMENTS_PATH)
    }
    provenance = _json_lines(PROVENANCE_PATH)
    custodians = {str(record["document_id"]): str(record["custodian"]) for record in provenance}
    source_uris = {str(record["document_id"]): str(record["source_uri"]) for record in provenance}

    inconsistent = sorted(
        document_id
        for document_id in labels
        if custody_facts(
            document_id=document_id,
            labels=labels,
            custodians=custodians,
            source_uris=source_uris,
        ).contradicts_label
    )
    expected = [designated_investigation().target_document_id]
    assert inconsistent == expected, (
        f"exactly one document should disagree with its custody record; found {inconsistent}"
    )
