"""Coldline.

===================

File:              tests/contract/test_retrieval_runtime.py
Component:         Contract tests — Retrieval runtime
Purpose:           Run the retrieval platform contracts inside the API container.
Interacts With:    Docker Compose, PostgreSQL with pgvector, LocalStack S3
Sprint/Task:       Sprint 2 — Project 2
Concepts:          Ingestion determinism, object boundary, hybrid arms, fusion evidence
Tools:             Python 3.12, pytest, Docker Compose
"""

import subprocess
from pathlib import Path

import pytest

TASK_ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.runtime


def test_retrieval_platform_preserves_its_runtime_contracts() -> None:
    """Catch a retrieval change that passes unit tests but fails on real services.

    The script runs inside the API container because PostgreSQL and LocalStack
    are reachable only on the Compose network. It is piped in on standard input
    so the container image needs no test files, exactly as the Sprint 1 adapter
    contract does.
    """
    verifier = (TASK_ROOT / "tests" / "contract" / "retrieval_runtime.py").read_text(
        encoding="utf-8"
    )
    result = subprocess.run(
        [
            "docker",
            "compose",
            "--profile",
            "observability",
            "--profile",
            "localstack",
            "exec",
            "-T",
            "api",
            "python",
            "-",
        ],
        cwd=TASK_ROOT,
        input=verifier,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=180,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Retrieval verification passed" in result.stdout
