"""Coldline.

===================

File:              tests/contract/test_supplied_retrieval_settings.py
Component:         Runtime contract — Supplied retrieval configuration
Purpose:           Verify that the product pipeline actually uses the checkpoint parameters.
Interacts With:    Retrieval stage telemetry and the protected configuration file
Sprint/Task:       Sprint 2 — Project 2 / Task 2.8
Concepts:          Configuration consistency, runtime evidence
Tools:             Python 3.12, pytest, httpx
"""

import httpx
import pytest

from tests.benchmark.config import STUDENT_PATH, load_config
from tests.golden import api_base_url

pytestmark = pytest.mark.runtime


def test_product_pipeline_uses_the_supplied_checkpoint_parameters() -> None:
    """The composed product endpoint must report the same parameters as its supplied file."""
    expected = load_config(STUDENT_PATH)
    response = httpx.post(
        f"{api_base_url()}/api/v1/retrieval/search",
        json={
            "query_id": "configuration-runtime-probe",
            "text": "temperature inspection procedure",
            "authorization": {"tenant_id": "tenant-coldline-ops", "clearance": "restricted"},
            "explain": True,
        },
        timeout=30.0,
    )
    response.raise_for_status()
    fusion = next(stage for stage in response.json()["stages"] if stage["stage"] == "fusion")
    assert fusion["note"] == (
        f"weighted reciprocal rank, dense_weight={expected.fusion_weight}, top_k={expected.top_k}"
    ), "the product pipeline is not using config/student/retrieval.yaml"
