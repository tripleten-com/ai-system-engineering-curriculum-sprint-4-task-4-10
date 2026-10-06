"""Coldline.

===================

File:              tests/unit/worker/test_bootstrap.py
Component:         Unit tests — Worker composition
Purpose:           Unit tests for the worker's provider, key check, request-log and procedure
                    composition.
Interacts With:    src/worker/bootstrap.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          Composition root, configuration flows inward, a key presented per use
Tools:             Python 3.12, pytest
"""

from pathlib import Path

import pytest

from adapters.model import (
    FileAuthenticationRecord,
    ResilientModelProvider,
    SecretStoreKeyAuthenticator,
)
from adapters.model.request_log import FileModelRequestLog
from domain.contracts import AccessTier
from tests.doubles import StubRetriever
from worker.bootstrap import compose_emulator, compose_model_provider, compose_procedures
from worker.config import WorkerSettings


def _settings(monkeypatch: pytest.MonkeyPatch, **overrides: str) -> WorkerSettings:
    """Build worker settings from the required addresses plus any override."""
    monkeypatch.setenv("COLDLINE_DATABASE_URL", "postgresql://user:pass@postgres:5432/coldline")
    monkeypatch.setenv("COLDLINE_REDIS_URL", "redis://redis:6379/0")
    monkeypatch.setenv("COLDLINE_OTEL_ENDPOINT", "http://jaeger:4317")
    monkeypatch.delenv("COLDLINE_MODEL_REQUEST_DIR", raising=False)
    monkeypatch.delenv("COLDLINE_PROVIDER_AUTH_RECORD", raising=False)
    for name, value in overrides.items():
        monkeypatch.setenv(f"COLDLINE_{name}", value)
    return WorkerSettings(_env_file=None)


def test_worker_presents_its_settings_key_read_per_use_and_composes_the_key_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The client's key is the settings' per-use read, and the provider side checks it."""
    settings = _settings(monkeypatch)

    emulator = compose_emulator(settings)

    assert emulator.key_reader == settings.provider_key
    assert emulator.provider_key == "", "no constant key: the read is awaited per request"
    assert isinstance(emulator.authenticator, SecretStoreKeyAuthenticator)
    assert emulator.authenticator.record is None
    assert isinstance(compose_model_provider(settings, emulator), ResilientModelProvider)


def test_worker_composes_the_authentication_record_from_the_configured_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """With a record file named the key check writes to it; without one it records nothing."""
    recording = compose_emulator(
        _settings(monkeypatch, PROVIDER_AUTH_RECORD=str(tmp_path / "provider-auth.json"))
    )
    authenticator = recording.authenticator
    assert isinstance(authenticator, SecretStoreKeyAuthenticator)
    assert isinstance(authenticator.record, FileAuthenticationRecord)
    assert authenticator.record.path == tmp_path / "provider-auth.json"


def test_worker_composes_the_request_log_from_the_configured_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """With a request directory the emulator records into it; without one it records nothing."""
    recording = compose_emulator(
        _settings(monkeypatch, MODEL_REQUEST_DIR=str(tmp_path / "model-requests"))
    )
    log = recording.request_log
    assert isinstance(log, FileModelRequestLog)
    assert log.directory == tmp_path / "model-requests"

    silent = compose_emulator(_settings(monkeypatch))
    assert silent.request_log is None


def test_worker_composes_procedure_retrieval_under_the_configured_tenancy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Procedure lookups run under the settings' tenancy with the restricted clearance."""
    settings = _settings(monkeypatch, PROCEDURE_TENANT="tenant-composition")

    lookup = compose_procedures(StubRetriever(()), settings)

    assert lookup.scope.tenant_id == "tenant-composition"
    assert lookup.scope.clearance is AccessTier.RESTRICTED
