"""Coldline.

===================

File:              tests/smoke/test_platform.py
Component:         Smoke tests — Local platform
Purpose:           Confirms that every supplied service initialized and can be inspected.
Interacts With:    Docker Compose, API, PostgreSQL, LocalStack SQS, observability stack
Sprint/Task:       Sprint 4 — Project 4
Concepts:          Readiness, deterministic provisioning, bounded diagnostics, redrive, SLO/alert,
                    OIDC discovery
Tools:             Python 3.12, pytest, httpx, Docker Compose
"""

import json
import subprocess
from pathlib import Path
from typing import Any

import httpx
import pytest

from tests.runtime_config import host_port

TASK_ROOT = Path(__file__).resolve().parents[2]
EXPECTED_SERVICES = {
    "alertmanager",
    "api",
    "grafana",
    "initializer",
    "issuer",
    "jaeger",
    "localstack",
    "postgres",
    "prometheus",
    "redis",
    "worker",
}
ISSUER_IDENTIFIER = "https://issuer.coldline.test"
pytestmark = pytest.mark.runtime


def _compose(*arguments: str) -> subprocess.CompletedProcess[str]:
    """Run one bounded Compose diagnostic from the Task root."""
    return subprocess.run(
        ["docker", "compose", "--profile", "observability", "--profile", "localstack", *arguments],
        cwd=TASK_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def _compose_rows() -> list[dict[str, Any]]:
    """Parse Compose JSON output across supported v2 output shapes."""
    result = _compose("ps", "-a", "--format", "json")
    assert result.returncode == 0, result.stderr
    output = result.stdout.strip()
    if not output:
        return []
    # Compose emits one JSON document per line. Parsing each line also works
    # across releases that change the amount of whitespace in their output.
    return [json.loads(line) for line in output.splitlines() if line.strip()]


def test_complete_service_roster_is_ready_or_completed() -> None:
    """Catch a missing process or initializer that did not finish successfully."""
    rows = _compose_rows()
    by_service = {row["Service"]: row for row in rows}

    assert set(by_service) == EXPECTED_SERVICES
    assert by_service["initializer"]["State"] == "exited"
    assert int(by_service["initializer"]["ExitCode"]) == 0
    for service in EXPECTED_SERVICES - {"initializer"}:
        assert by_service[service]["State"] == "running"


def test_api_and_worker_dependency_readiness_is_healthy() -> None:
    """Catch a stack that is running but cannot reach its required dependencies."""
    api_port = host_port("COLDLINE_API_HOST_PORT", 8000)
    response = httpx.get(f"http://localhost:{api_port}/health/ready", timeout=5.0)
    assert response.status_code == 200
    assert response.json() == {"status": "ready"}

    result = _compose("exec", "-T", "worker", "python", "-m", "worker.health")
    assert result.returncode == 0, result.stdout + result.stderr


def test_application_processes_run_as_non_root_users() -> None:
    """Catch an image or Compose override that restores root privileges."""
    for service in ("api", "worker"):
        result = _compose("exec", "-T", service, "id", "-u")
        assert result.returncode == 0, result.stdout + result.stderr
        assert result.stdout.strip() != "0"


def test_database_and_queue_were_initialized() -> None:
    """Catch a one-shot initializer that left storage or queue state absent."""
    table = _compose(
        "exec",
        "-T",
        "postgres",
        "psql",
        "-U",
        "coldline",
        "-d",
        "coldline",
        "-tAc",
        "SELECT to_regclass('public.exceptions');",
    )
    assert table.returncode == 0, table.stderr
    assert table.stdout.strip() == "exceptions"

    # Task 3.3 retires Redis Streams as the JobQueue transport; the initializer
    # provisions the SQS main and dead-letter queues instead, and Redis carries
    # no queue state to inspect anymore.
    queue = _compose(
        "exec",
        "-T",
        "worker",
        "python",
        "-c",
        (
            "from adapters.queue import create_sqs_client\n"
            "from worker.config import WorkerSettings\n"
            "settings = WorkerSettings()\n"
            "client = create_sqs_client(\n"
            "    endpoint_url=settings.s3_endpoint,\n"
            "    region_name=settings.s3_region,\n"
            "    access_key_id=settings.s3_access_key_id,\n"
            "    secret_access_key=settings.s3_secret_access_key,\n"
            ")\n"
            "client.get_queue_url(QueueName=settings.queue_name)\n"
            "client.get_queue_url(QueueName=f'{settings.queue_name}-dlq')\n"
            "print('queues provisioned')\n"
        ),
    )
    assert queue.returncode == 0, queue.stdout + queue.stderr
    assert "queues provisioned" in queue.stdout

    # Sprint 2 adds the retrieval corpus schema and the pgvector extension.
    # Provisioning them is initialization work, not ingestion: the tables and
    # the extension must exist even before `poe ingest` runs.
    corpus = _compose(
        "exec",
        "-T",
        "postgres",
        "psql",
        "-U",
        "coldline",
        "-d",
        "coldline",
        "-tAc",
        "SELECT to_regclass('public.documents'), to_regclass('public.chunks'), "
        "(SELECT count(*) FROM pg_extension WHERE extname = 'vector');",
    )
    assert corpus.returncode == 0, corpus.stderr
    assert corpus.stdout.strip() == "documents|chunks|1", corpus.stdout


def test_object_storage_bucket_was_provisioned() -> None:
    """Catch an initializer that left the corpus bucket or its artifacts absent."""
    api_port = host_port("COLDLINE_API_HOST_PORT", 8000)
    response = httpx.get(
        f"http://localhost:{api_port}/api/v1/corpus/objects",
        params={"prefix": "corpus/"},
        timeout=10.0,
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["keys"] == ["corpus/documents.jsonl", "corpus/provenance.jsonl"], payload


def test_observability_services_are_provisioned() -> None:
    """Catch an available observability UI that has no usable supplied configuration."""
    prometheus_port = host_port("COLDLINE_PROMETHEUS_HOST_PORT", 9090)
    grafana_port = host_port("COLDLINE_GRAFANA_HOST_PORT", 3000)
    jaeger_port = host_port("COLDLINE_JAEGER_HOST_PORT", 16686)
    alertmanager_port = host_port("COLDLINE_ALERTMANAGER_HOST_PORT", 9093)

    prometheus = httpx.get(f"http://localhost:{prometheus_port}/api/v1/targets", timeout=5.0).json()
    active_targets = prometheus["data"]["activeTargets"]
    assert {target["labels"]["job"] for target in active_targets} == {
        "coldline-api",
        "coldline-worker",
    }
    assert all(target["health"] == "up" for target in active_targets)

    dashboard = httpx.get(
        f"http://localhost:{grafana_port}/api/search",
        params={"query": "Coldline Diagnostics"},
        timeout=5.0,
    )
    dashboard.raise_for_status()
    assert any(item["uid"] == "coldline-diagnostics" for item in dashboard.json())

    jaeger = httpx.get(f"http://localhost:{jaeger_port}/api/services", timeout=5.0)
    jaeger.raise_for_status()
    assert "data" in jaeger.json()

    # Task 3.4 adds Alertmanager. Its status endpoint being reachable confirms
    # it loaded its supplied configuration; whether any alert is currently
    # active is exercised separately, by tests/contract/test_slo_alert.py.
    alertmanager = httpx.get(f"http://localhost:{alertmanager_port}/api/v2/status", timeout=5.0)
    alertmanager.raise_for_status()
    assert "versionInfo" in alertmanager.json()


def test_deployed_alert_rule_is_loaded() -> None:
    """Catch a rule file Prometheus failed to load or wire to Alertmanager."""
    prometheus_port = host_port("COLDLINE_PROMETHEUS_HOST_PORT", 9090)
    rules = httpx.get(f"http://localhost:{prometheus_port}/api/v1/rules", timeout=5.0).json()
    names = {rule.get("name") for group in rules["data"]["groups"] for rule in group["rules"]}
    assert "ColdlineDeadLetterQueueBacklog" in names


def test_token_issuer_publishes_its_discovery_document_and_one_key() -> None:
    """Catch an issuer that is up but serves the wrong documents, or a key set that drifted.

    Task 4.2 adds the issuer. Its discovery document names the fixed issuer identifier
    and a `jwks_uri` on the host port actually published; the key set at that URL holds
    exactly one signing key with one declared algorithm, which is what `config/auth.yaml`
    pins.
    """
    issuer_port = host_port("COLDLINE_ISSUER_HOST_PORT", 8180)
    discovery = httpx.get(
        f"http://localhost:{issuer_port}/.well-known/openid-configuration", timeout=5.0
    )
    discovery.raise_for_status()
    document = discovery.json()
    assert document["issuer"] == ISSUER_IDENTIFIER
    assert document["jwks_uri"] == f"http://localhost:{issuer_port}/.well-known/jwks.json"

    key_set = httpx.get(document["jwks_uri"], timeout=5.0)
    key_set.raise_for_status()
    keys = key_set.json()["keys"]
    assert len(keys) == 1, keys
    assert keys[0]["kty"] == "RSA" and keys[0]["use"] == "sig"
    assert [keys[0]["alg"]] == document["id_token_signing_alg_values_supported"]
    assert "d" not in keys[0], "the published key set must hold the public half only"
