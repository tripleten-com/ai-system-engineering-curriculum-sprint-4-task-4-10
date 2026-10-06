"""Coldline.

===================

File:              src/api/v2_contracts.py
Component:         API — Version 2 request and response contracts
Purpose:           Publish the evolved payload shapes for the two supported v2 operations.
Interacts With:    The student v2 router and the API contract checks
Sprint/Task:       Sprint 2 — Project 2 / Task 2.5
Concepts:          API versioning, backward compatibility
Tools:             Python 3.12, FastAPI, Pydantic

These contracts are supplied and protected. Task 2.5 asks a student to build
one versioned route and protect its write path, not to invent a schema, so the
evolved shapes are published here and the checks compare against them.

Each v2 contract adds one required field the v1 contract does not carry. That
is the whole evolution: it is a breaking change for a v1 caller, which is
exactly why it needs a new version rather than an edit to the v1 route.
"""

from pydantic import BaseModel, ConfigDict, Field

from domain.contracts import DocumentRecord, SensorReading

DOCUMENTS_OPERATION_ID = "documents_v2_create"
READINGS_OPERATION_ID = "readings_v2_accept"
SUPPORTED_OPERATION_IDS = (DOCUMENTS_OPERATION_ID, READINGS_OPERATION_ID)

DOCUMENTS_V2_PATH = "/api/v2/documents"
READINGS_V2_PATH = "/api/v2/readings"
OPERATION_PATHS = {
    DOCUMENTS_OPERATION_ID: DOCUMENTS_V2_PATH,
    READINGS_OPERATION_ID: READINGS_V2_PATH,
}


class DocumentV2Request(BaseModel):
    """Carry one document plus the system that submitted it."""

    model_config = ConfigDict(extra="forbid")

    document: DocumentRecord
    source_system: str = Field(min_length=1, max_length=120)
    """Required in v2 and absent from v1: which upstream system sent this."""


class DocumentV2Response(BaseModel):
    """Return the stored document identity, its chunk count, and its source."""

    model_config = ConfigDict(extra="forbid")

    document_id: str
    chunk_count: int = Field(ge=0)
    source_system: str


class ReadingV2Request(BaseModel):
    """Carry one sensor reading plus the operator who reported it."""

    model_config = ConfigDict(extra="forbid")

    reading: SensorReading
    reported_by: str = Field(min_length=1, max_length=120)
    """Required in v2 and absent from v1: who reported this reading."""


class ReadingV2Response(BaseModel):
    """Return the accepted exception identity, its state, and its reporter."""

    model_config = ConfigDict(extra="forbid")

    exception_id: str
    state: str
    reported_by: str
    status_url: str
