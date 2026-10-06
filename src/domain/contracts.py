"""Coldline.

===================

File:              src/domain/contracts.py
Component:         Domain — Contracts
Purpose:           Define provider-neutral contracts for exception processing and retrieval.
Interacts With:    API and worker use cases
Sprint/Task:       Sprint 4 — Project 4
Concepts:          Business rules, immutable contracts, state, retrieval evidence
Tools:             Python 3.12, Pydantic

The Project 4 opening checkpoint changes three contracts. ``SensorReading`` gains an
optional free-text ``handling_note``, ``ModelRequest`` carries that note and the
procedure excerpt the worker retrieves beside the reading, and the model-provider
port answers with ``ModelAnswer``, the provider's raw text, which the worker parses
into ``ModelSummary`` itself.

The Task 4.3 checkpoint adds the ``NEEDS_REVIEW`` state, the three fields the
output policy stores on a record (``handling_class``, ``next_step``,
``rejection_reason``), and the development-only ``emulator_response`` selector that
``poe scenario --response`` sets to make the model emulator answer with one of its
supplied responses.
"""

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ExceptionState(StrEnum):
    """Describe the observable lifecycle of one exception.

    ``NEEDS_REVIEW`` (Task 4.3) is a finished state beside ``COMPLETED`` and
    ``FAILED``: the provider answered, the answer failed the output check, and
    a dispatcher must review the exception before anyone acts on it.
    ``docs/security/output-policy.md`` is the rule.
    """

    RECEIVED = "RECEIVED"
    QUEUED = "QUEUED"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    NEEDS_REVIEW = "NEEDS_REVIEW"


class SensorReading(BaseModel):
    """Represent one synthetic shipment sensor observation.

    ``handling_note`` is free text typed by whoever dispatches the shipment at
    the sensor gateway. It is carried as written: the supplied redaction covers
    the bounded ``context`` field only, and nothing on the ingest path reads
    the note. The note travels with the reading into the stored record, the
    queued job, and the worker's model request.

    ``emulator_response`` is a development-only selector. It names one of the
    supplied responses of the deterministic model emulator (``valid``,
    ``malformed``, ``manipulated``); ``poe scenario --response`` sets it, the
    worker copies it into the model request, and the emulator answers with that
    response. Absent, the emulator answers its default valid document. A hosted
    provider would never see this field; it exists so the supplied bad answers
    can be produced on request through the whole stack.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    reading_id: str = Field(min_length=1, max_length=80)
    shipment_id: str = Field(min_length=1, max_length=80)
    temperature_c: float
    allowed_min_c: float
    allowed_max_c: float
    recorded_at: datetime
    context: str = Field(default="", max_length=500)
    handling_note: str | None = Field(default=None, max_length=1_000)
    emulator_response: str | None = Field(default=None, max_length=40, pattern=r"^[a-z][a-z0-9-]*$")

    @model_validator(mode="after")
    def validate_range(self) -> "SensorReading":
        """Reject a handling range whose minimum is not below its maximum."""
        if self.allowed_min_c >= self.allowed_max_c:
            raise ValueError("allowed_min_c must be below allowed_max_c")
        return self


class ExceptionJob(BaseModel):
    """Carry one validated exception across the queue boundary."""

    model_config = ConfigDict(frozen=True)

    exception_id: str
    reading: SensorReading
    accepted_at: datetime


class JobDelivery(BaseModel):
    """Describe one provider-neutral queue delivery attempt."""

    model_config = ConfigDict(frozen=True)

    message_id: str
    job: ExceptionJob
    delivery_count: int = Field(ge=1)
    trace_carrier: dict[str, str] = Field(default_factory=dict)


class ModelRequest(BaseModel):
    """Describe the provider-neutral input for an exception summary.

    Beside the reading's identity and temperatures, the request carries the
    handling note exactly as the reading holds it and the excerpt of the
    procedure the worker retrieved for the excursion. Both are text other
    parties wrote: the note at the gateway, the excerpt by whoever authored
    the corpus document. ``emulator_response`` is the reading's development-only
    selector, copied through so the emulator can answer with a supplied response.
    """

    model_config = ConfigDict(frozen=True)

    exception_id: str
    shipment_id: str
    temperature_c: float
    allowed_min_c: float
    allowed_max_c: float
    handling_note: str | None = None
    procedure_id: str | None = None
    procedure_excerpt: str = ""
    emulator_response: str | None = None


class ModelAnswer(BaseModel):
    """Carry one provider's raw answer text back to the worker.

    ``text`` is whatever the provider returned, unparsed. The deterministic
    emulator writes a JSON document there; from Task 4.3 the worker passes that
    text through the supplied guardrail before storing anything from it.
    """

    model_config = ConfigDict(frozen=True)

    provider: str
    text: str


class ModelSummary(BaseModel):
    """Describe the parsed provider response stored by Coldline."""

    model_config = ConfigDict(frozen=True)

    summary: str
    provider: str


class ExceptionRecord(BaseModel):
    """Represent the durable state of one exception workflow.

    ``handling_class`` and ``next_step`` are the validated schema fields a
    ``COMPLETED`` record stores beside its summary; ``rejection_reason`` is the
    guardrail's reason code a ``NEEDS_REVIEW`` record stores beside the output
    policy's fixed message. ``failure_reason`` stays the field of ``FAILED``.
    """

    model_config = ConfigDict(frozen=True)

    exception_id: str
    reading: SensorReading
    state: ExceptionState
    accepted_at: datetime
    updated_at: datetime
    summary: str | None = None
    failure_reason: str | None = None
    handling_class: str | None = None
    next_step: str | None = None
    rejection_reason: str | None = None


class AccessTier(StrEnum):
    """Describe the two classification tiers carried by the supplied corpus."""

    STANDARD = "standard"
    RESTRICTED = "restricted"


class AccessLabel(BaseModel):
    """Carry the tenancy and classification labels attached to stored content.

    Every document and every chunk derived from it keeps the same label. The
    data layer, the retrieval adapter, and the diagnostic stage evidence all
    read this one representation so an access decision cannot be made from a
    second, divergent copy of the same fact.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    tenant_id: str = Field(min_length=1, max_length=80, pattern=r"^[a-z0-9][a-z0-9-]*$")
    access_tier: AccessTier


class Provenance(BaseModel):
    """Record where one supplied document came from and which revision it is."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_uri: str = Field(min_length=1, max_length=300)
    custodian: str = Field(min_length=1, max_length=120)
    revision: str = Field(min_length=1, max_length=40)
    recorded_at: datetime


class DocumentRecord(BaseModel):
    """Represent one whole supplied procedure, handling rule, or playbook."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    document_id: str = Field(min_length=1, max_length=120, pattern=r"^[a-z0-9][a-z0-9-]*$")
    title: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1)
    access: AccessLabel
    provenance: Provenance


class ChunkRecord(BaseModel):
    """Represent one deterministic slice of a document with its search fields.

    ``chunk_id`` is derived from the document identity and the chunk position,
    so re-ingesting the same corpus produces the same identifiers. The label
    and provenance are copied from the parent document rather than recomputed,
    which is what lets retrieval evidence name a chunk's origin and custody.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    chunk_id: str = Field(min_length=1, max_length=140)
    document_id: str = Field(min_length=1, max_length=120)
    chunk_index: int = Field(ge=0)
    text: str = Field(min_length=1)
    embedding: tuple[float, ...]
    access: AccessLabel
    provenance: Provenance

    @model_validator(mode="after")
    def validate_identity(self) -> "ChunkRecord":
        """Reject a chunk whose identifier does not match its document position."""
        expected = f"{self.document_id}#{self.chunk_index:04d}"
        if self.chunk_id != expected:
            raise ValueError(f"chunk_id must be {expected}")
        if not self.embedding:
            raise ValueError("embedding must not be empty")
        return self


class AuthorizationContext(BaseModel):
    """Carry the caller's tenancy and clearance through the retrieval request.

    The published ``Retriever`` contract accepts this context from Task 2.1
    onward. Whether the supplied adapter *enforces* it is a separate, recorded
    fact: see ``RetrievalResult.authorization_enforced``.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    tenant_id: str = Field(min_length=1, max_length=80, pattern=r"^[a-z0-9][a-z0-9-]*$")
    clearance: AccessTier


class RetrievalRequest(BaseModel):
    """Describe one hybrid retrieval request and its controlled parameters."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    query_id: str = Field(min_length=1, max_length=120)
    text: str = Field(min_length=1, max_length=1000)
    authorization: AuthorizationContext
    top_k: int = Field(ge=1, le=50)
    dense_weight: float = Field(ge=0.0, le=1.0)
    # Ask the adapter for the extra authorization-pool evidence. Ordinary
    # request handling and the benchmark harness leave this False so no
    # diagnostic query is added to a measured path; the Task 2.8 stage
    # inspector sets it to True.
    explain: bool = False


class RetrievalStage(StrEnum):
    """Name the four observable stages of the supplied retrieval pipeline."""

    DENSE = "dense"
    SPARSE = "sparse"
    AUTHORIZATION = "authorization"
    FUSION = "fusion"


class Candidate(BaseModel):
    """Represent one ranked chunk produced by a retrieval stage.

    The chunk text travels with the candidate so that assembling prompt
    context needs no second read, and so that a citation can name the chunk's
    tenancy and custody without a join.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    chunk_id: str = Field(min_length=1, max_length=140)
    document_id: str = Field(min_length=1, max_length=120)
    rank: int = Field(ge=1)
    score: float
    text: str = Field(min_length=1)
    access: AccessLabel
    provenance_revision: str = Field(min_length=1, max_length=40)


class StageEvidence(BaseModel):
    """Record what one stage admitted and what it removed.

    The identifiers are the evidence a Task 2.8 attribution rests on: a chunk
    listed in ``admitted`` reached that stage, and a chunk listed in
    ``dropped`` was removed by it. Both lists are ordered exactly as the stage
    produced them.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    stage: RetrievalStage
    admitted: tuple[str, ...]
    dropped: tuple[str, ...] = ()
    note: str = Field(default="", max_length=300)


class RetrievalResult(BaseModel):
    """Carry the final ranked chunks together with per-stage evidence."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    query_id: str = Field(min_length=1, max_length=120)
    results: tuple[Candidate, ...]
    stages: tuple[StageEvidence, ...]
    authorization_enforced: bool

    def stage(self, stage: RetrievalStage) -> StageEvidence:
        """Return the evidence recorded for one stage or fail loudly."""
        for evidence in self.stages:
            if evidence.stage is stage:
                return evidence
        raise KeyError(f"no evidence recorded for stage {stage.value}")


class AssembledContext(BaseModel):
    """Carry the prompt-ready context and citations built from retrieved chunks."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    query_id: str = Field(min_length=1, max_length=120)
    prompt_context: str
    citations: tuple[str, ...]
    token_budget: int = Field(ge=1)
    used_tokens: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_budget(self) -> "AssembledContext":
        """Reject an assembled context that exceeds its declared token budget."""
        if self.used_tokens > self.token_budget:
            raise ValueError("used_tokens must not exceed token_budget")
        return self
