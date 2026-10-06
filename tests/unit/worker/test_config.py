"""Coldline.

===================

File:              tests/unit/worker/test_config.py
Component:         Unit tests — Test Config
Purpose:           Unit tests for the worker configuration boundary's supplied settings.
Interacts With:    One isolated source responsibility
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          Fast feedback, failure paths, state invariants
Tools:             Python 3.12, pytest, Redis, Pydantic

The provider key's read (``provider_key``) is the student's work in Task 4.5 and is
assessed by `poe config-binding` and the assessed module; nothing here reads it, so these
tests hold on the starter and on a completion alike.
"""

import pytest
from pydantic import ValidationError

from worker.config import WorkerSettings


def _settings(monkeypatch: pytest.MonkeyPatch) -> WorkerSettings:
    """Build settings from the three required dependency addresses only."""
    monkeypatch.setenv("COLDLINE_DATABASE_URL", "postgresql://user:pass@postgres:5432/coldline")
    monkeypatch.setenv("COLDLINE_REDIS_URL", "redis://redis:6379/0")
    monkeypatch.setenv("COLDLINE_OTEL_ENDPOINT", "http://jaeger:4317")
    monkeypatch.delenv("COLDLINE_MODEL_REQUEST_DIR", raising=False)
    monkeypatch.delenv("COLDLINE_PROVIDER_AUTH_RECORD", raising=False)
    return WorkerSettings(_env_file=None)


def test_worker_settings_require_dependency_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    """The worker must not silently invent working dependency credentials."""
    monkeypatch.delenv("COLDLINE_DATABASE_URL", raising=False)
    monkeypatch.delenv("COLDLINE_REDIS_URL", raising=False)
    monkeypatch.delenv("COLDLINE_OTEL_ENDPOINT", raising=False)

    with pytest.raises(ValidationError):
        WorkerSettings(_env_file=None)


def test_worker_settings_keep_the_bounded_retry_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    """Compose values must retain three attempts and 30-second stale claiming."""
    settings = _settings(monkeypatch)

    assert settings.maximum_attempts == 3
    assert settings.stale_message_ms == 30_000
    assert settings.model_latency_ms == 250


def test_worker_settings_record_no_model_requests_unless_a_directory_is_named(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The request directory is off by default; compose.yaml names it for the worker container."""
    assert _settings(monkeypatch).model_request_dir is None

    monkeypatch.setenv("COLDLINE_MODEL_REQUEST_DIR", "/home/coldline/model-requests")
    assert WorkerSettings(_env_file=None).model_request_dir == "/home/coldline/model-requests"


def test_worker_settings_keep_no_authentication_record_unless_a_file_is_named(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The authentication record is off by default; compose.yaml names it for the container."""
    assert _settings(monkeypatch).provider_auth_record is None

    monkeypatch.setenv("COLDLINE_PROVIDER_AUTH_RECORD", "/home/coldline/provider-auth.json")
    settings = WorkerSettings(_env_file=None)
    assert settings.provider_auth_record == "/home/coldline/provider-auth.json"


def test_worker_settings_carry_the_localstack_endpoint_the_secret_adapter_reuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The four LocalStack settings the queue uses are what `secret_provider(settings)` reads."""
    settings = _settings(monkeypatch)

    assert settings.s3_endpoint == "http://localstack:4566"
    assert settings.s3_region == "us-east-1"
    assert settings.s3_access_key_id and settings.s3_secret_access_key


def test_worker_settings_name_the_procedure_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    """Procedure retrieval runs under one fixed tenancy with a bounded candidate count."""
    settings = _settings(monkeypatch)

    assert settings.procedure_tenant == "tenant-northwind"
    assert 1 <= settings.procedure_top_k <= 12
