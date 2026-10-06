"""Coldline.

===================

File:              tests/unit/api/test_config.py
Component:         Unit tests — Test Config
Purpose:           Unit tests for the API configuration boundary.
Interacts With:    One isolated source responsibility
Sprint/Task:       Sprint 3 — Project 3
Concepts:          Fast feedback, failure paths, state invariants, dead-letter redrive
Tools:             Python 3.12, pytest, Redis, LocalStack, Pydantic
"""

import pytest
from pydantic import ValidationError

from api.config import ApiSettings

COMPOSE_VALUES = {
    "COLDLINE_DATABASE_URL": "postgresql://user:pass@postgres:5432/coldline",
    "COLDLINE_REDIS_URL": "redis://redis:6379/0",
    "COLDLINE_OTEL_ENDPOINT": "http://jaeger:4317",
    "COLDLINE_S3_ENDPOINT": "http://localstack:4566",
    # Task 3.3's dead-letter redrive policy: no default, so every settings
    # construction in this file must supply both.
    "COLDLINE_QUEUE_VISIBILITY_TIMEOUT_SECONDS": "30",
    "COLDLINE_QUEUE_MAX_RECEIVE_COUNT": "3",
}


def test_api_settings_require_dependency_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    """The API must not silently invent working dependency credentials."""
    for name in COMPOSE_VALUES:
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(ValidationError):
        ApiSettings(_env_file=None)


def test_api_settings_require_the_object_storage_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Object storage has no working default; an absent endpoint must fail startup."""
    for name, value in COMPOSE_VALUES.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("COLDLINE_S3_ENDPOINT")

    with pytest.raises(ValidationError, match="s3_endpoint"):
        ApiSettings(_env_file=None)


def test_api_settings_parse_the_compose_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    """The protected config module must validate the supplied Compose values."""
    for name, value in COMPOSE_VALUES.items():
        monkeypatch.setenv(name, value)

    settings = ApiSettings(_env_file=None)

    assert settings.service_name == "coldline-api"
    assert settings.stream_name == "coldline.exception.jobs"
    assert settings.s3_bucket == "coldline-corpus"
    assert (settings.retrieval_top_k, settings.retrieval_dense_weight) == (3, 0.5)


def test_api_settings_reject_an_out_of_range_retrieval_parameter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The two controlled parameters have published ranges, enforced at startup."""
    for name, value in COMPOSE_VALUES.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("COLDLINE_RETRIEVAL_DENSE_WEIGHT", "1.5")

    with pytest.raises(ValidationError, match="retrieval_dense_weight"):
        ApiSettings(_env_file=None)
