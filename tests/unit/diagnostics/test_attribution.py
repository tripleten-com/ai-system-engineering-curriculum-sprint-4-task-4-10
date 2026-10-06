"""Coldline.

===================

File:              tests/unit/diagnostics/test_attribution.py
Component:         Unit tests — Stage attribution rule
Purpose:           Check the published rule isolates each stage from the right evidence.
Interacts With:    tests/diagnostics/attribution.py
Sprint/Task:       Sprint 2 — Project 2 / Task 2.8
Concepts:          Root-cause isolation, ordered decision rules
Tools:             Python 3.12, pytest
"""

import pytest

from tests.diagnostics.attribution import (
    AUTHORIZATION_FILTERING,
    CHUNKING,
    EMBEDDING,
    FUSION,
    NO_DEFECT,
    SPARSE_MATCHING,
    STAGES,
    AttributionError,
    ChunkFacts,
    CustodyFacts,
    StageObservation,
    attribute,
    chunk_facts,
    custody_facts,
    custody_lines,
    evidence_lines,
    ruled_out,
    tokens,
)

TARGET = "doc-a#0001"
OTHER = "doc-b#0000"


def observation(
    *,
    readable: bool = True,
    dropped: bool = False,
    dense: bool = False,
    sparse: bool = False,
    fusion: bool = False,
    retrieved: bool = False,
) -> StageObservation:
    """Build one stage observation from the presence flags that matter."""
    return StageObservation(
        target_chunk_id=TARGET,
        readable_pool=(TARGET, OTHER) if readable else (OTHER,),
        authorization_dropped=(TARGET,) if dropped else (),
        dense_candidates=(TARGET, OTHER) if dense else (OTHER,),
        sparse_candidates=(TARGET, OTHER) if sparse else (OTHER,),
        fusion_input=(TARGET, OTHER) if fusion else (OTHER,),
        final_results=(TARGET,) if retrieved else (OTHER,),
    )


def facts(*, split: bool, terms: int = 3) -> ChunkFacts:
    """Build chunking evidence that is either split or whole."""
    shared = frozenset(f"term{index}" for index in range(terms))
    per_chunk = (
        tuple(frozenset({term}) for term in sorted(shared))
        if split
        else (shared, frozenset({next(iter(shared))}))
    )
    return ChunkFacts(
        document_id="doc-a",
        chunk_ids=tuple(f"doc-a#{index:04d}" for index in range(len(per_chunk))),
        shared_terms=shared,
        terms_per_chunk=per_chunk,
    )


def custody(*, mislabelled: bool = True, corroborating: int = 5) -> CustodyFacts:
    """Build custody evidence that either contradicts the label or agrees with it.

    `mislabelled` is the designated case: the custodian's other documents all
    sit in one tenancy and this label names another. Agreement is the contrast
    case. `corroborating=0` is the third shape - a custodian nothing else
    shares - where consistency is unobserved rather than proven.
    """
    labelled = "tenant-b" if mislabelled else "tenant-a"
    return CustodyFacts(
        document_id="doc-a",
        labelled_tenant_id=labelled,
        custodian="A operations desk",
        source_uri="s3://corpus/source/doc-a.md",
        custodian_tenancies=frozenset({"tenant-a"}) if corroborating else frozenset(),
        corroborating_documents=corroborating,
    )


def test_tokenization_is_the_documented_rule() -> None:
    """The token rule must be the one the fixtures and the README describe."""
    assert tokens("Who signs off, before the container may be opened?") == {
        "signs",
        "before",
        "container",
        "opened",
    }
    # Shorter than four characters, or a listed stop word.
    assert tokens("the box is not that big") == set()


def test_a_thin_overlap_leaves_chunking_unobserved() -> None:
    """One shared term proves nothing about the split, in either direction."""
    thin = ChunkFacts(
        document_id="doc-a",
        chunk_ids=("doc-a#0000", "doc-a#0001"),
        shared_terms=frozenset({"container"}),
        terms_per_chunk=(frozenset({"container"}), frozenset()),
    )

    assert not thin.is_split
    assert thin.whole_chunk_ids == ()
    assert CHUNKING not in ruled_out(observation(sparse=True, fusion=True), thin, custody())


def test_a_split_is_only_claimed_when_no_chunk_holds_every_term() -> None:
    """The split evidence is exactly the absence of a passage holding all of it."""
    assert facts(split=True).is_split
    assert facts(split=True).whole_chunk_ids == ()
    assert not facts(split=False).is_split
    assert facts(split=False).whole_chunk_ids == ("doc-a#0000",)


@pytest.mark.parametrize(
    "given,expected",
    [
        (observation(readable=False), AUTHORIZATION_FILTERING),
        (observation(dropped=True, dense=True, sparse=True), AUTHORIZATION_FILTERING),
        (observation(sparse=True, fusion=True), EMBEDDING),
        (observation(dense=True, fusion=True), SPARSE_MATCHING),
        (observation(dense=True, sparse=True, fusion=True), FUSION),
    ],
    ids=[
        "never-readable",
        "dropped-by-the-constraint",
        "sparse-only",
        "dense-only",
        "both-arms-then-suppressed",
    ],
)
def test_each_stage_is_isolated_by_its_own_evidence(given: StageObservation, expected: str) -> None:
    """Every stage in the enum must be reachable from evidence that implies it."""
    assert attribute(given, facts(split=False), custody()) == expected


def test_a_split_is_attributed_only_when_neither_arm_found_the_chunk() -> None:
    """Chunking explains a miss when no passage carried the answer to either arm."""
    assert attribute(observation(), facts(split=True), custody()) == CHUNKING


def test_authorization_outranks_every_later_stage() -> None:
    """A chunk the caller may not read was not lost by ranking or by representation."""
    dropped = observation(readable=False, dense=True, sparse=True, fusion=True)

    assert attribute(dropped, facts(split=True), custody()) == AUTHORIZATION_FILTERING


def test_one_arm_finding_the_chunk_outranks_fusion() -> None:
    """Fusion cannot be blamed for a candidate only one arm ever offered it.

    This is the lesson's own common mistake, and the ordering of the rule is
    what prevents it.
    """
    assert (
        attribute(observation(sparse=True, fusion=True), facts(split=True), custody()) == EMBEDDING
    )


def test_a_retrieved_chunk_has_no_miss_to_attribute() -> None:
    """Attributing a success would be attributing a failure that did not happen."""
    with pytest.raises(AttributionError, match="no miss"):
        attribute(
            observation(dense=True, sparse=True, fusion=True, retrieved=True),
            facts(split=False),
            custody(),
        )


def test_evidence_that_isolates_nothing_is_refused() -> None:
    """A readable chunk neither arm found, with no split, isolates no single stage."""
    with pytest.raises(AttributionError, match="does not isolate"):
        attribute(observation(), facts(split=False), custody())


def test_only_positively_observed_stages_are_ruled_out() -> None:
    """Absence of evidence never exonerates a stage."""
    proven = ruled_out(observation(sparse=True, fusion=True), facts(split=False), custody())

    assert proven == {AUTHORIZATION_FILTERING, SPARSE_MATCHING, CHUNKING}
    # The dense arm never saw the chunk, so nothing is known about it, and the
    # miss means fusion did not return it.
    assert EMBEDDING not in proven
    assert FUSION not in proven


def test_fusion_is_ruled_out_only_when_it_returned_the_chunk() -> None:
    """Fusion is exonerated by returning the chunk, not by having received it."""
    assert FUSION not in ruled_out(observation(fusion=True), facts(split=False), custody())
    assert FUSION in ruled_out(
        observation(dense=True, sparse=True, fusion=True, retrieved=True),
        facts(split=False),
        custody(),
    )


def test_the_attributed_stage_is_never_also_ruled_out() -> None:
    """A stage cannot be both the cause and proven fine, on any evidence shape."""
    shapes = [
        (observation(readable=False), facts(split=False)),
        (observation(), facts(split=True)),
        (observation(sparse=True, fusion=True), facts(split=False)),
        (observation(dense=True, fusion=True), facts(split=False)),
        (observation(dense=True, sparse=True, fusion=True), facts(split=False)),
    ]
    for given, chunking in shapes:
        attributed = attribute(given, chunking, custody())
        assert attributed in STAGES
        assert attributed not in ruled_out(given, chunking, custody())


def test_chunk_facts_are_derived_from_the_committed_text() -> None:
    """The chunking evidence must come from the fixtures, not from the database."""
    derived = chunk_facts(
        query_text="who confirms the material class before the container is opened",
        document_id="doc-a",
        title="Handling rule: spill containment",
        chunk_texts={
            "doc-a#0000": "Do not ventilate the container until the",
            "doc-a#0001": "safety officer confirms the material class.",
        },
    )

    assert derived.shared_terms == {"confirms", "material", "class", "container"}
    assert derived.is_split
    assert derived.whole_chunk_ids == ()


def test_evidence_lines_name_every_stage() -> None:
    """The printed evidence must cover each stage a student may attribute to."""
    lines = evidence_lines(observation(sparse=True, fusion=True), facts(split=False))

    assert len(lines) == 5
    for stage in ("authorization", "chunking", "dense", "sparse", "fusion"):
        assert any(line.startswith(stage) for line in lines), stage


def test_a_denial_of_correctly_labelled_content_is_not_a_defect() -> None:
    """The one question the ordered rule has to ask first.

    An access boundary that withholds another tenancy's content is working. A
    rule that returned `authorization_filtering` here would teach a student to
    file the system's correct behavior as a fault, which ADR009-R06 forbids.
    """
    verdict = attribute(observation(readable=False), facts(split=False), custody(mislabelled=False))

    assert verdict == NO_DEFECT
    assert verdict not in STAGES


def test_a_denial_caused_by_a_mislabel_is_a_defect() -> None:
    """The same drop, with the label contradicted, is the designated fault."""
    verdict = attribute(observation(readable=False), facts(split=False), custody())

    assert verdict == AUTHORIZATION_FILTERING


def test_an_uncorroborated_custody_record_is_not_evidence_of_a_mislabel() -> None:
    """A custodian nothing else shares cannot show a label is wrong.

    Consistency is then unobserved, and the conservative reading is the right
    one: the rule declines to call the denial a defect rather than inferring a
    mislabel from a record with nothing to compare against.
    """
    alone = custody(corroborating=0)

    assert not alone.is_corroborated
    assert not alone.contradicts_label
    assert attribute(observation(readable=False), facts(split=False), alone) == NO_DEFECT


def test_a_correct_denial_exonerates_the_stage_that_made_it() -> None:
    """The one case where a stage that withheld the chunk is proven, not unobserved."""
    proven = ruled_out(observation(readable=False), facts(split=False), custody(mislabelled=False))

    assert AUTHORIZATION_FILTERING in proven


def test_a_mislabelled_denial_never_exonerates_the_stage() -> None:
    """The cause of a miss cannot also be ruled out."""
    proven = ruled_out(observation(readable=False), facts(split=False), custody())

    assert AUTHORIZATION_FILTERING not in proven


def test_custody_facts_are_derived_from_the_corpus_not_declared() -> None:
    """What makes a label wrong is that every other document disagrees with it."""
    labels = {
        "doc-a": "tenant-b",
        "doc-b": "tenant-a",
        "doc-c": "tenant-a",
        "doc-d": "tenant-z",
    }
    custodians = {
        "doc-a": "A operations desk",
        "doc-b": "A operations desk",
        "doc-c": "A operations desk",
        "doc-d": "Z operations desk",
    }
    uris = {name: f"s3://corpus/source/{name}.md" for name in labels}

    mislabelled = custody_facts(
        document_id="doc-a", labels=labels, custodians=custodians, source_uris=uris
    )
    assert mislabelled.corroborating_documents == 2
    assert mislabelled.expected_tenant_ids == ("tenant-a",)
    assert mislabelled.contradicts_label

    consistent = custody_facts(
        document_id="doc-b", labels=labels, custodians=custodians, source_uris=uris
    )
    assert not consistent.contradicts_label

    # doc-d's desk holds nothing else, so its label has no corroboration.
    alone = custody_facts(
        document_id="doc-d", labels=labels, custodians=custodians, source_uris=uris
    )
    assert not alone.is_corroborated
    assert not alone.contradicts_label


def test_custody_facts_refuse_a_document_the_corpus_does_not_hold() -> None:
    """Silently returning "consistent" for an unknown document would hide a fault."""
    with pytest.raises(AttributionError, match="not in the supplied corpus"):
        custody_facts(document_id="doc-x", labels={}, custodians={}, source_uris={})


def test_the_custody_evidence_is_printed_for_a_reader() -> None:
    """The comparison has to be visible, or a student cannot check the rule."""
    mislabelled = custody_lines(custody())
    assert any("labelled tenant tenant-b" in line for line in mislabelled)
    assert any("this one is not" in line for line in mislabelled)

    consistent = custody_lines(custody(mislabelled=False))
    assert any("agrees with" in line for line in consistent)

    alone = custody_lines(custody(corroborating=0))
    assert any("nothing corroborates" in line for line in alone)
