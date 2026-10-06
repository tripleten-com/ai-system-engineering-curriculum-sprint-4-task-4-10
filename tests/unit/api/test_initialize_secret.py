"""Coldline.

===================

File:              tests/unit/api/test_initialize_secret.py
Component:         Unit tests — The initializer's secret provisioning
Purpose:           Prove the initializer creates the provider key's secret under the documented
                    name with the first version's value, through the supplied adapter, with the
                    bounded retry.
Interacts With:    src/api/initialize.py, src/adapters/secrets/localstack.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          Idempotent provisioning, composition root
Tools:             Python 3.12, pytest
"""

from typing import Any

import pytest

from adapters.secrets import FIRST_VERSION_VALUE, PROVIDER_KEY_SECRET_NAME, LocalStackSecretProvider
from api import initialize
from api.config import ApiSettings


def _settings(monkeypatch: pytest.MonkeyPatch) -> ApiSettings:
    monkeypatch.setenv("COLDLINE_DATABASE_URL", "postgresql://user:pass@postgres:5432/coldline")
    monkeypatch.setenv("COLDLINE_REDIS_URL", "redis://redis:6379/0")
    monkeypatch.setenv("COLDLINE_OTEL_ENDPOINT", "http://jaeger:4317")
    monkeypatch.setenv("COLDLINE_S3_ENDPOINT", "http://localstack:4566")
    monkeypatch.setenv("COLDLINE_QUEUE_VISIBILITY_TIMEOUT_SECONDS", "30")
    monkeypatch.setenv("COLDLINE_QUEUE_MAX_RECEIVE_COUNT", "3")
    return ApiSettings(_env_file=None)


async def test_the_initializer_creates_the_provider_secret_with_the_first_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The documented name, the opening literal as the first value, the LocalStack endpoint."""
    calls: list[dict[str, Any]] = []

    async def fake_ensure(store: LocalStackSecretProvider, **kwargs: Any) -> None:
        calls.append({"store": store, **kwargs})

    monkeypatch.setattr(initialize, "ensure_secret_when_ready", fake_ensure)

    await initialize._provision_provider_secret(_settings(monkeypatch))

    [call] = calls
    assert isinstance(call["store"], LocalStackSecretProvider)
    assert call["name"] == PROVIDER_KEY_SECRET_NAME == "coldline/worker/model-provider-key"
    # The comparison is made first and only its outcome is asserted: pytest renders the
    # operands of a comparison it rewrites, and the expected operand is the first version's
    # value (tests/unit/security/test_value_findings.py proves the failing path prints none).
    matches_initial = call["first_value"] == FIRST_VERSION_VALUE
    assert matches_initial, "the initializer must provision the supplied first version"
    assert call["endpoint"] == "http://localstack:4566"
    assert call["attempts"] == initialize.LOCALSTACK_ATTEMPTS
    assert call["store"]._client.meta.endpoint_url == "http://localstack:4566"
