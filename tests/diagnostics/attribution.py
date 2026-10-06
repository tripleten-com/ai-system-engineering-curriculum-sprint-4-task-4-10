"""Coldline.

===================

File:              tests/diagnostics/attribution.py
Component:         Diagnostics — Stage attribution rule
Purpose:           Derive a miss attribution and its ruled-out stages from stage evidence.
Interacts With:    The retrieval stage evidence and the committed corpus fixtures
Sprint/Task:       Sprint 2 — Project 2 / Task 2.8
Concepts:          Root-cause isolation, evidence-derived conclusions
Tools:             Python 3.12

Supplied and protected. This module *is* the published attribution rule: the
diagnostic prints the evidence, this decides what the evidence supports, and the
assessed checks compare a recorded answer against the same decision. Nothing is
hardcoded to one query or one stage.

The rule is ordered, and the order matters. "Candidate fusion suppressed it" is
only a coherent conclusion when both arms actually offered the chunk to fusion;
a chunk that one arm never surfaced was not lost by ranking, it was lost by
retrieval. So fusion is considered last, and only after both arms are excluded.

One question comes before all five, and it is the one an ordered stage rule
gets wrong most easily. When the authorization stage removed the target chunk,
that is not by itself a defect: an access boundary that withholds another
tenancy's content is the boundary working. Blaming the stage for doing its job
would teach exactly the wrong lesson, so the rule asks first whether the
content was *supposed* to be readable, and answers it from the evidence rather
than from the fixture's own say-so.

The evidence is the corpus's custody records. Every document carries both an
access label and a custody record naming the desk that owns it, and across the
corpus each custodian appears under exactly one tenancy. So a document whose
label puts it in one tenancy while every other document from the same custodian
sits in another is internally inconsistent - and a denial caused by that
inconsistency is a defect in the labelling, not a boundary decision. A denial
of content whose label and custody agree is correct, and the rule says so.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

CHUNKING = "chunking"
EMBEDDING = "embedding"
SPARSE_MATCHING = "sparse_matching"
AUTHORIZATION_FILTERING = "authorization_filtering"
FUSION = "fusion"
STAGES = (CHUNKING, EMBEDDING, SPARSE_MATCHING, AUTHORIZATION_FILTERING, FUSION)

# Not a stage, and deliberately absent from the answer contract: it is what the
# rule returns when the miss is correct behavior rather than a fault. A student
# cannot record it, because the designated investigation is a defect. It exists
# so the rule can decline to blame a stage that did its job, and so the
# contrast case can be checked rather than described.
NO_DEFECT = "no_defect"

# The same tokenization the corpus and the cached judge evidence document:
# lowercase, split on every run of characters outside a-z0-9, discard tokens
# shorter than four characters, discard these stop words. Keeping one rule for
# every text comparison in this repository is what makes the chunking evidence
# re-derivable from the committed fixtures.
MINIMUM_TOKEN_LENGTH = 4
STOP_WORDS = frozenset(
    {"been", "does", "each", "from", "have", "must", "that", "then", "this", "when", "with"}
)
_TOKEN = re.compile(r"[^a-z0-9]+")
# A single shared term proves nothing about how a document was split, so a
# split is only claimable when at least two of the query's terms occur in the
# document at all.
MINIMUM_SPLIT_TERMS = 2


class AttributionError(ValueError):
    """Report evidence the published rule cannot attribute."""


def tokens(text: str) -> set[str]:
    """Return the documented content-token set of one text."""
    return {
        token
        for token in _TOKEN.split(text.lower())
        if len(token) >= MINIMUM_TOKEN_LENGTH and token not in STOP_WORDS
    }


@dataclass(frozen=True)
class ChunkFacts:
    """How one document was split, and where a query's terms landed."""

    document_id: str
    chunk_ids: tuple[str, ...]
    shared_terms: frozenset[str]
    terms_per_chunk: tuple[frozenset[str], ...]

    @property
    def is_split(self) -> bool:
        """Return whether the query's terms are spread across chunk boundaries.

        True when the document holds at least two of the query's terms and no
        single chunk holds all of them. That is the observable consequence of
        fixed-width chunking: the material that answers the question exists,
        and no one passage contains it.
        """
        if len(self.shared_terms) < MINIMUM_SPLIT_TERMS:
            return False
        return not any(self.shared_terms <= terms for terms in self.terms_per_chunk)

    @property
    def whole_chunk_ids(self) -> tuple[str, ...]:
        """Return the chunks that hold every one of the query's shared terms.

        Empty when the document holds fewer than two of the query's terms. One
        shared term in one chunk is not evidence that the split preserved
        anything, so a thin overlap leaves chunking unobserved rather than
        proven fine.
        """
        if len(self.shared_terms) < MINIMUM_SPLIT_TERMS:
            return ()
        return tuple(
            chunk_id
            for chunk_id, terms in zip(self.chunk_ids, self.terms_per_chunk, strict=True)
            if self.shared_terms <= terms
        )


def chunk_facts(
    *, query_text: str, document_id: str, title: str, chunk_texts: dict[str, str]
) -> ChunkFacts:
    """Return the chunking evidence for one query against one document."""
    query_terms = tokens(query_text)
    document_terms = tokens(title) | {
        token for text in chunk_texts.values() for token in tokens(text)
    }
    ordered = tuple(sorted(chunk_texts))
    return ChunkFacts(
        document_id=document_id,
        chunk_ids=ordered,
        shared_terms=frozenset(query_terms & document_terms),
        terms_per_chunk=tuple(
            frozenset(tokens(title) | tokens(chunk_texts[chunk_id])) for chunk_id in ordered
        ),
    )


@dataclass(frozen=True)
class CustodyFacts:
    """Whether one document's access label agrees with its custody record.

    `custodian_tenancies` is every tenancy that *other* documents from the same
    custodian are labelled with. Deriving it from the corpus rather than from a
    declared policy keeps the evidence checkable: a reader can see that five
    other documents from this desk sit in one tenancy and this one does not.
    """

    document_id: str
    labelled_tenant_id: str
    custodian: str
    source_uri: str
    custodian_tenancies: frozenset[str]
    corroborating_documents: int

    @property
    def is_corroborated(self) -> bool:
        """Return whether any other document shares this custodian.

        A custodian that appears once says nothing about where its content
        belongs, so consistency is then *unobserved* rather than proven either
        way. The rule treats that as "no evidence of a mislabel", which is the
        conservative reading: it declines to call a denial a defect on a
        record nothing corroborates.
        """
        return self.corroborating_documents > 0

    @property
    def contradicts_label(self) -> bool:
        """Return whether the custody record disagrees with the access label."""
        if not self.is_corroborated:
            return False
        return self.labelled_tenant_id not in self.custodian_tenancies

    @property
    def expected_tenant_ids(self) -> tuple[str, ...]:
        """Return the tenancy the custody record points to, if it points at one."""
        return tuple(sorted(self.custodian_tenancies))


def custody_facts(
    *,
    document_id: str,
    labels: dict[str, str],
    custodians: dict[str, str],
    source_uris: dict[str, str],
) -> CustodyFacts:
    """Return the custody evidence for one document, derived from the corpus.

    `labels` maps every document to its labelled tenancy and `custodians` to
    its recorded custodian, both read from the committed fixtures. The target
    document is excluded from its own corroboration: a label cannot confirm
    itself.
    """
    if document_id not in labels:
        raise AttributionError(f"{document_id} is not in the supplied corpus")
    if document_id not in custodians:
        raise AttributionError(f"{document_id} has no custody record")
    custodian = custodians[document_id]
    tenancies = {
        labels[other]
        for other, desk in custodians.items()
        if desk == custodian and other != document_id and other in labels
    }
    corroborating = sum(
        1
        for other, desk in custodians.items()
        if desk == custodian and other != document_id and other in labels
    )
    return CustodyFacts(
        document_id=document_id,
        labelled_tenant_id=labels[document_id],
        custodian=custodian,
        source_uri=source_uris.get(document_id, ""),
        custodian_tenancies=frozenset(tenancies),
        corroborating_documents=corroborating,
    )


@dataclass(frozen=True)
class StageObservation:
    """Where one target chunk was seen, and where it was not."""

    target_chunk_id: str
    readable_pool: tuple[str, ...]
    authorization_dropped: tuple[str, ...]
    dense_candidates: tuple[str, ...]
    sparse_candidates: tuple[str, ...]
    fusion_input: tuple[str, ...]
    final_results: tuple[str, ...]

    @property
    def readable(self) -> bool:
        """Return whether the authorization stage made the target chunk readable."""
        return self.target_chunk_id in self.readable_pool

    @property
    def dropped_by_authorization(self) -> bool:
        """Return whether the authorization stage removed the target chunk."""
        return self.target_chunk_id in self.authorization_dropped

    @property
    def in_dense(self) -> bool:
        """Return whether the dense arm surfaced the target chunk."""
        return self.target_chunk_id in self.dense_candidates

    @property
    def in_sparse(self) -> bool:
        """Return whether the sparse arm surfaced the target chunk."""
        return self.target_chunk_id in self.sparse_candidates

    @property
    def reached_fusion(self) -> bool:
        """Return whether the target chunk was offered to candidate fusion."""
        return self.target_chunk_id in self.fusion_input

    @property
    def retrieved(self) -> bool:
        """Return whether the target chunk reached the final ranked results."""
        return self.target_chunk_id in self.final_results


def attribute(observation: StageObservation, facts: ChunkFacts, custody: CustodyFacts) -> str:
    """Return the one stage this evidence attributes the miss to.

    The order is the rule. Read it as a sequence of questions, each of which is
    only meaningful once the previous one has been answered no.

    Returns `NO_DEFECT` when the miss is correct behavior: the authorization
    stage withheld content whose access label and custody record agree, which
    is the boundary working rather than a fault in it.
    """
    if observation.retrieved:
        raise AttributionError(
            f"{observation.target_chunk_id} reached the final results, so there is no miss "
            "to attribute"
        )
    if not observation.readable or observation.dropped_by_authorization:
        # The chunk was never readable for this caller, so nothing downstream
        # had the chance to lose it. Whether that is a defect depends on
        # whether it was supposed to be readable, and the custody record is
        # what answers that.
        if custody.contradicts_label:
            return AUTHORIZATION_FILTERING
        return NO_DEFECT
    if not observation.in_dense and not observation.in_sparse:
        if facts.is_split:
            # Neither arm found it, and the material that answers the question
            # is spread across chunk boundaries: no single passage carries it.
            return CHUNKING
        raise AttributionError(
            f"{observation.target_chunk_id} was readable and reached neither search arm, and "
            f"the query's terms are not split across the chunks of {facts.document_id}. This "
            "evidence does not isolate a single stage."
        )
    if observation.in_sparse and not observation.in_dense:
        # Text search surfaced it and vector search did not: the failure is in
        # the dense representation, not in ranking.
        return EMBEDDING
    if observation.in_dense and not observation.in_sparse:
        return SPARSE_MATCHING
    # Both arms offered it and it still did not come out: ranking suppressed it.
    return FUSION


def ruled_out(
    observation: StageObservation, facts: ChunkFacts, custody: CustodyFacts | None = None
) -> frozenset[str]:
    """Return every stage this evidence proves operated normally on the target.

    "Operated normally" means the evidence positively shows the stage did its
    job for this chunk. Absence of evidence never counts: a stage that never
    saw the chunk is not exonerated by that, it is simply unobserved.
    """
    proven: set[str] = set()
    if observation.readable and not observation.dropped_by_authorization:
        proven.add(AUTHORIZATION_FILTERING)
    elif custody is not None and not custody.contradicts_label:
        # The stage withheld the chunk, and the label it acted on agrees with
        # the custody record. It applied the boundary to correctly labelled
        # content, which is the stage operating normally. Without this, a
        # correct denial would leave authorization merely unobserved and no
        # evidence could ever exonerate it.
        proven.add(AUTHORIZATION_FILTERING)
    if facts.whole_chunk_ids:
        proven.add(CHUNKING)
    if observation.in_dense:
        proven.add(EMBEDDING)
    if observation.in_sparse:
        proven.add(SPARSE_MATCHING)
    if observation.reached_fusion and observation.retrieved:
        proven.add(FUSION)
    return frozenset(proven)


def custody_lines(custody: CustodyFacts) -> list[str]:
    """Return the custody evidence a reader can check against the fixtures."""
    expected = custody.expected_tenant_ids
    if not custody.is_corroborated:
        verdict = "no other document shares this custodian, so nothing corroborates the label"
    elif custody.contradicts_label:
        verdict = (
            f"every one of the {custody.corroborating_documents} other documents from this "
            f"custodian is labelled {', '.join(expected)} - this one is not"
        )
    else:
        verdict = (
            f"the label agrees with the {custody.corroborating_documents} other documents "
            "from this custodian"
        )
    return [
        f"custody        {custody.document_id} labelled tenant {custody.labelled_tenant_id}",
        f"               custodian {custody.custodian!r}",
        f"               source {custody.source_uri}",
        f"               {verdict}",
    ]


def evidence_lines(observation: StageObservation, facts: ChunkFacts) -> list[str]:
    """Return the one-line-per-stage evidence a reader can check by hand."""
    target = observation.target_chunk_id
    return [
        f"authorization  readable pool holds {target}: {observation.readable}"
        f"; removed by the constraint: {observation.dropped_by_authorization}"
        f"; pool size {len(observation.readable_pool)}",
        f"chunking       {facts.document_id} split into {len(facts.chunk_ids)} chunks"
        f"; query terms also in the document: {sorted(facts.shared_terms) or '(none)'}"
        f"; chunks holding all of them: {list(facts.whole_chunk_ids) or '(none)'}",
        f"dense          candidate list holds {target}: {observation.in_dense}"
        f" ({len(observation.dense_candidates)} candidates)",
        f"sparse         candidate list holds {target}: {observation.in_sparse}"
        f" ({len(observation.sparse_candidates)} candidates)",
        f"fusion         offered {target}: {observation.reached_fusion}"
        f"; returned it: {observation.retrieved}"
        f" ({len(observation.final_results)} results)",
    ]
