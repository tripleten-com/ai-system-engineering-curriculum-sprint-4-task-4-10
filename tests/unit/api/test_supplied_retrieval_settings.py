"""Coldline.

===================

File:              tests/unit/api/test_supplied_retrieval_settings.py
Component:         Unit tests — Supplied retrieval configuration
Purpose:           Require the product composition to load the supplied checkpoint parameters.
Interacts With:    API configuration and the protected retrieval configuration file
Sprint/Task:       Sprint 3 — Project 3
Concepts:          Configuration consistency, fail-closed startup, dead-letter redrive
Tools:             Python 3.12, pytest
"""

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from api import config

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


@pytest.mark.parametrize(("top_k", "weight"), [(8, 0.5), (7, 0.2)])
def test_composition_settings_use_the_supplied_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, top_k: int, weight: float
) -> None:
    """Both protected parameters must reach the settings used by the product workflow."""
    for name, value in COMPOSE_VALUES.items():
        monkeypatch.setenv(name, value)
    source = tmp_path / "retrieval.yaml"
    source.write_text(yaml.safe_dump({"retrieval": {"top_k": top_k, "fusion_weight": weight}}))
    settings = config.load_api_settings(source)
    assert settings.retrieval_top_k == top_k
    assert settings.retrieval_dense_weight == weight


@pytest.mark.parametrize(
    "document",
    [
        {},
        {"retrieval": {"top_k": True, "fusion_weight": 0.5}},
        {"retrieval": {"top_k": 13, "fusion_weight": 0.5}},
        {"retrieval": {"top_k": 8, "fusion_weight": 1.1}},
        {"retrieval": {"top_k": 8, "fusion_weight": 0.5, "typo": 1}},
    ],
)
def test_invalid_checkpoint_configuration_fails_startup(tmp_path: Path, document: dict) -> None:
    """Missing, misspelled, or unhonorable parameters must not silently use defaults."""
    source = tmp_path / "retrieval.yaml"
    source.write_text(yaml.safe_dump(document))
    with pytest.raises(ValidationError):
        config.load_api_settings(source)


def test_missing_checkpoint_configuration_fails_startup(tmp_path: Path) -> None:
    """The declared checkpoint is required, rather than an optional tuning hint."""
    with pytest.raises(FileNotFoundError):
        config.load_api_settings(tmp_path / "missing.yaml")
