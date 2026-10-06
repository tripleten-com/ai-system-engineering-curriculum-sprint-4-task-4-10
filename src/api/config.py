"""Coldline.

===================

File:              src/api/config.py
Component:         API — Config
Purpose:           Own and validate every API environment read.
Interacts With:    FastAPI, domain, ports, and adapters
Sprint/Task:       Sprint 4 — Project 4
Concepts:          HTTP boundary, composition, configuration ownership, dead-letter redrive
Tools:             Python 3.12, Redis, PostgreSQL, LocalStack, Pydantic
"""

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ApiSettings(BaseSettings):
    """Describe the protected runtime configuration for the API service.

    This module is the only place in the API runtime that reads the
    environment. The composition root validates it once and passes values
    inward, so no route, use case, or adapter reaches for a variable itself.

    The object-storage and queue credentials below are LocalStack development
    values. They are not secrets, they grant nothing outside this local
    Compose network, and they must never be replaced with a real account
    credential in this repository. Managed deployments supply credentials
    through their own protected configuration.
    """

    model_config = SettingsConfigDict(env_prefix="COLDLINE_", extra="forbid")

    database_url: str = Field(min_length=1)
    redis_url: str = Field(min_length=1)
    otel_endpoint: str = Field(min_length=1)
    service_name: str = "coldline-api"
    # Vestigial: named the retired Redis Streams key and consumer group. Nothing
    # reads either field anymore; left at their original values rather than
    # renamed, since SQS naming rules never applied to a field nothing uses.
    stream_name: str = "coldline.exception.jobs"
    consumer_group: str = "coldline-workers"

    s3_endpoint: str = Field(min_length=1)
    s3_bucket: str = Field(default="coldline-corpus", min_length=3, max_length=63)
    s3_region: str = Field(default="us-east-1", min_length=2)
    s3_access_key_id: str = Field(default="localstack-development-key", min_length=1)
    s3_secret_access_key: str = Field(default="localstack-development-secret", min_length=1)

    # Task 3.3 queue identity. LocalStack serves SQS through the same edge port
    # as S3, so the queue client reuses s3_endpoint/s3_region/the LocalStack
    # development credentials above rather than duplicating them under a new name.
    queue_name: str = Field(default="coldline-exception-jobs", min_length=1)
    dead_letter_queue_name: str = Field(default="coldline-exception-jobs-dlq", min_length=1)
    # Task 3.3's dead-letter redrive policy. These two have no default: the
    # initializer provisions the queue and its dead-letter binding from
    # whatever this Task's environment supplies, inside the published bounds
    # in docs/student/task-3-3-contract.md, and fails outright until it does.
    queue_visibility_timeout_seconds: int = Field(ge=5, le=300)
    queue_max_receive_count: int = Field(ge=1, le=10)

    # Supplied retrieval defaults for Tasks 2.1 through 2.6. Task 2.7 adds one
    # bounded student-editable override file for exactly these two values.
    retrieval_top_k: int = Field(default=3, ge=1, le=50)
    retrieval_dense_weight: float = Field(default=0.5, ge=0.0, le=1.0)
    retrieval_token_budget: int = Field(default=320, ge=32, le=4_000)

    # Task 3.1 release identity. Both values are baked into the image by the release
    # manifest's build arguments. `build_version` is what /version answers, so two
    # builds of the same source stay distinguishable from outside. `ready_delay_seconds`
    # makes the candidate release warm up slowly: readiness answers 503 until the process
    # has been serving for that long, which is what a health gate must hold traffic from.
    build_version: str = Field(default="dev", min_length=1, max_length=64)
    ready_delay_seconds: float = Field(default=0.0, ge=0.0, le=120.0)

    # Task 4.2: where the API fetches the issuer's key set from. config/auth.yaml names the
    # host-reachable `jwks_url` a browser and `poe token-check` open (localhost and the
    # issuer's published host port). Inside the Compose network that host port does not
    # exist, so compose.yaml sets this to the issuer's in-network origin and the
    # TokenVerifier swaps the origin while keeping the path; unset, as on the host, the
    # URL is used as written.
    issuer_jwks_origin: str | None = None


class SuppliedRetrievalParameters(BaseModel):
    """Validate the same bounded parameters accepted by the experiment harness."""

    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)
    top_k: int = Field(strict=True, ge=1, le=12)
    fusion_weight: float = Field(strict=True, ge=0.0, le=1.0)


class SuppliedRetrievalFile(BaseModel):
    """Reject misspelled or missing top-level configuration keys."""

    model_config = ConfigDict(extra="forbid")
    retrieval: SuppliedRetrievalParameters


SUPPLIED_RETRIEVAL_PATH = Path(__file__).resolve().parents[2] / "config/student/retrieval.yaml"


def load_api_settings(retrieval_path: Path = SUPPLIED_RETRIEVAL_PATH) -> ApiSettings:
    """Compose Task 2.8 onward from its supplied file and infrastructure environment.

    These two protected checkpoint parameters take precedence over inherited
    environment defaults. Other process settings still come from the environment.
    Loading this configuration does not establish an approved adoption decision.
    """
    supplied = SuppliedRetrievalFile.model_validate(
        yaml.safe_load(retrieval_path.read_text(encoding="utf-8"))
    ).retrieval
    return ApiSettings(  # type: ignore[call-arg]  # infrastructure comes from the environment
        retrieval_top_k=supplied.top_k,
        retrieval_dense_weight=supplied.fusion_weight,
    )
