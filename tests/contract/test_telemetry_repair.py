"""Coldline.

===================

File:              tests/contract/test_telemetry_repair.py
Component:         Contract — Telemetry repair
Purpose:           Grade the Task 1.3 trace-propagation and metric fixes.
Interacts With:    Redis Streams adapter, worker metrics, live runtime stack
Sprint/Task:       Sprint 1 — Project 1
Concepts:          Distributed tracing, metric cardinality, contract testing
Tools:             Python 3.12, pytest, OpenTelemetry, Prometheus, Docker Compose

Note on runtime addressing:
    This checkpoint's ``compose.yaml`` (inherited from Task 1.1) does not publish Redis or
    the worker's metrics port to the host — only the API, Jaeger, Prometheus, and Grafana
    are reachable from outside the Docker network (see ``tests/runtime_config.py`` and
    ``compose.yaml``). The existing runtime-contract precedent for reaching Redis directly
    is ``tests/contract/runtime_adapters.py`` + ``tests/contract/test_runtime_adapters.py``,
    which run their verification code inside the ``worker`` container via
    ``docker compose exec``. These tests follow the same established pattern instead of
    assuming host-reachable Redis/worker-metrics endpoints.
"""

import asyncio
import math
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from prometheus_client.parser import text_string_to_metric_families

from tests.e2e.test_exception_workflow import (
    _load_unique_reading,
    _wait_for_service_evidence,
    _wait_for_terminal,
)
from tests.runtime_config import host_port
from tests.security.fixtures import bearer_headers

TASK_ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.runtime

# Runs inside the `worker` container, which already has network access to Redis and the
# same `adapters`/`domain` code installed. Prints a success marker on the happy path;
# an unmet assertion raises inside the container and surfaces in the captured stderr
# traceback, which the host-side test folds into its own failure message.
_TRACE_PROPAGATION_SCRIPT = """
import asyncio
import uuid
from datetime import UTC, datetime

from opentelemetry import trace
from opentelemetry.propagate import extract
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from redis.asyncio import Redis

from adapters.queue.redis_streams import RedisJobQueue
from domain.contracts import ExceptionJob, SensorReading


async def main() -> None:
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(InMemorySpanExporter()))
    tracer = provider.get_tracer("test_telemetry_repair")

    redis = Redis.from_url("redis://redis:6379/0")
    stream = f"test-propagation-{uuid.uuid4().hex}"
    group = "test-group"
    queue = RedisJobQueue(redis, stream=stream, group=group, consumer="test-consumer")
    try:
        await queue.initialize()

        job = ExceptionJob(
            exception_id=f"exc-{uuid.uuid4().hex}",
            reading=SensorReading(
                reading_id="r-1",
                shipment_id="s-1",
                temperature_c=20.0,
                allowed_min_c=0.0,
                allowed_max_c=10.0,
                recorded_at=datetime.now(UTC),
            ),
            accepted_at=datetime.now(UTC),
        )

        with tracer.start_as_current_span("test.publish") as publish_span:
            publish_trace_id = publish_span.get_span_context().trace_id
            await queue.publish(job)

        delivery = await queue.read(block_ms=2000)
        assert delivery is not None

        assert delivery.trace_carrier, "publish() did not inject any trace carrier headers"

        extracted_context = extract(delivery.trace_carrier)
        with tracer.start_as_current_span(
            "test.worker_process", context=extracted_context
        ) as worker_span:
            worker_trace_id = worker_span.get_span_context().trace_id

        assert worker_trace_id == publish_trace_id, (
            "worker span started a new trace instead of continuing the publisher's trace — "
            "trace context is not propagating across the Redis Streams boundary"
        )
    finally:
        await redis.delete(stream)
        await redis.aclose()


asyncio.run(main())
print("TRACE_PROPAGATION_OK")
"""

# Fetches the worker's own /metrics endpoint from inside its own container, since that
# port is not published to the host in this checkpoint's compose topology.
_READ_WORKER_METRICS_SCRIPT = (
    "import urllib.request; "
    "print(urllib.request.urlopen('http://localhost:9100/metrics', timeout=5).read().decode())"
)


def _run_script_in_worker(script: str) -> subprocess.CompletedProcess[str]:
    """Pipe one script to `python -` inside the running `worker` container."""
    return subprocess.run(
        ["docker", "compose", "exec", "-T", "worker", "python", "-"],
        cwd=TASK_ROOT,
        input=script,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
        check=False,
    )


def _read_worker_metrics() -> subprocess.CompletedProcess[str]:
    """Run `-c <snippet>` inside the running `worker` container to fetch its /metrics."""
    return subprocess.run(
        ["docker", "compose", "exec", "-T", "worker", "python", "-c", _READ_WORKER_METRICS_SCRIPT],
        cwd=TASK_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
        check=False,
    )


def test_trace_propagation_script_is_valid_python() -> None:
    """Guard the embedded worker-side script against syntax errors ruff/mypy cannot see.

    ``_TRACE_PROPAGATION_SCRIPT`` is piped to a subprocess's stdin rather than imported,
    so it is invisible to this project's usual lint/typecheck tooling. This cheap
    ``compile()`` check at least catches a syntax error before it turns into a confusing
    subprocess failure.
    """
    compile(_TRACE_PROPAGATION_SCRIPT, "<trace_propagation_script>", "exec")


def test_trace_context_survives_the_redis_streams_round_trip() -> None:
    """Require the real HTTP publisher and worker loop to form one parent chain."""
    _, reading = _load_unique_reading()
    api_port = host_port("COLDLINE_API_HOST_PORT", 8000)
    with httpx.Client(base_url=f"http://localhost:{api_port}", timeout=10) as client:
        response = client.post("/api/v1/readings", json=reading)
        assert response.status_code == 202
        accepted = response.json()
        record = _wait_for_terminal(client, accepted["status_url"])
        assert record["summary"] and record["failure_reason"] is None
        replay = client.post("/api/v1/readings", json=reading)
        assert replay.status_code == 202
        assert replay.json()["exception_id"] == accepted["exception_id"]
        normal = {**reading, "reading_id": f"normal-{uuid.uuid4().hex}", "temperature_c": 5}
        assert client.post("/api/v1/readings", json=normal).status_code == 422
    api_traces = _wait_for_service_evidence("coldline-api", accepted["exception_id"])
    worker_traces = _wait_for_service_evidence("coldline-worker", accepted["exception_id"])
    assert api_traces and worker_traces, "Both live services must export trace evidence"
    publications = {
        (span["traceID"], span["spanID"])
        for item in api_traces
        for span in item["spans"]
        if span["operationName"] == "job_queue.publish"
    }
    workers = [
        span
        for item in worker_traces
        for span in item["spans"]
        if span["operationName"] == "coldline.process_exception"
    ]
    assert publications and workers
    assert any(
        (span["traceID"], ref["spanID"]) in publications
        and ref["traceID"] == span["traceID"]
        and ref["refType"] == "CHILD_OF"
        for span in workers
        for ref in span["references"]
    ), "The actual worker loop must continue the API publishing span, not create a root"
    result = _run_script_in_worker(_TRACE_PROPAGATION_SCRIPT)
    assert result.returncode == 0 and "TRACE_PROPAGATION_OK" in result.stdout, (
        result.stdout + result.stderr
    )


def test_metric_has_no_unbound_labels() -> None:
    """The processing-duration histogram must not carry a per-request label."""
    from worker.metrics import PROCESSING_DURATION

    bounded_values = {
        "status": {"COMPLETED", "FAILED"},
        "outcome": {"completed", "failed", "success", "failure"},
        "disposition": {"ACK", "ACK_EXISTING", "ACK_MISSING", "RETRY"},
    }
    label_names = PROCESSING_DURATION._labelnames
    assert set(label_names) <= bounded_values.keys(), (
        "Use an aggregate or the documented bounded status/outcome/disposition dimensions"
    )
    result = _read_worker_metrics()
    assert result.returncode == 0, result.stdout + result.stderr
    for family in text_string_to_metric_families(result.stdout):
        for sample in family.samples:
            if sample.name.startswith("coldline_exception_processing_duration_seconds"):
                for label, value in sample.labels.items():
                    if label != "le":
                        assert label in bounded_values and value in bounded_values[label], (
                            "Histogram application dimensions must use finite documented values"
                        )


def _sum_bucket_values(metrics_text: str, *, le: str) -> float:
    """Sum every processing-duration bucket sample at the given `le`, across any labels.

    Summing rather than filtering by a specific label keeps this comparable before and
    after the next checkpoint's real fix, which removes the `request_id` label from
    `PROCESSING_DURATION` entirely (see `test_metric_has_no_unbound_labels`) — so a
    `request_id`-keyed filter would find zero samples once that fix lands, even though
    the unit bug this test targets is a separate, orthogonal defect.
    """
    target = f'le="{le}"'
    total = 0.0
    for line in metrics_text.splitlines():
        if (
            line.startswith("coldline_exception_processing_duration_seconds_bucket")
            and target in line
        ):
            total += float(line.rsplit(" ", 1)[-1])
    return total


async def test_metric_records_real_seconds_not_milliseconds() -> None:
    """A sub-second exception must not show up thousands of times too large in the histogram.

    Isolates the one observation this test triggers with a before/after delta on the
    le="5.0" bucket total (summed across whatever labels the histogram currently
    carries), rather than filtering by `request_id`: that label is a separate defect
    the next checkpoint removes entirely, so a `request_id`-keyed filter would break once both
    defects are correctly fixed together, even though the unit bug would be fixed too.
    """
    result = _run_script_in_worker("""
from datetime import UTC, datetime, timedelta
import inspect
from worker.metrics import PROCESSING_DURATION, observe_processing_duration
start = datetime(2026, 1, 1, tzinfo=UTC)
parameters = inspect.signature(observe_processing_duration).parameters
values = {"request_id": "unit-contract", "status": "COMPLETED",
          "outcome": "completed", "disposition": "ACK"}
kwargs = {name: value for name, value in values.items() if name in parameters}
observe_processing_duration(start, start + timedelta(seconds=0.25), **kwargs)
samples = [s for m in PROCESSING_DURATION.collect() for s in m.samples]
assert sum(s.value for s in samples if s.name.endswith("_count")) == 1
total = sum(s.value for s in samples if s.name.endswith("_sum"))
assert abs(total - 0.25) < 1e-9, "histogram must record seconds"
""")
    assert result.returncode == 0, result.stdout + result.stderr
    before = _read_worker_metrics()
    assert before.returncode == 0, before.stdout + before.stderr
    before_le_5s = _sum_bucket_values(before.stdout, le="5.0")

    api_port = host_port("COLDLINE_API_HOST_PORT", 8000)
    async with httpx.AsyncClient(base_url=f"http://localhost:{api_port}", timeout=10.0) as client:
        response = await client.post(
            "/api/v1/readings",
            json={
                "reading_id": f"r-{uuid.uuid4().hex}",
                "shipment_id": f"s-{uuid.uuid4().hex}",
                "temperature_c": 20.0,
                "allowed_min_c": 0.0,
                "allowed_max_c": 10.0,
                "recorded_at": datetime.now(UTC).isoformat(),
            },
        )
        assert response.status_code == 202
        accepted_body = response.json()

        record: dict[str, object] | None = None
        for _ in range(30):
            # As the dispatcher: from Task 4.2 the summary endpoint requires the token.
            status_response = await client.get(
                accepted_body["status_url"], headers=bearer_headers("dispatcher-valid")
            )
            status_response.raise_for_status()
            record = status_response.json()
            if record["state"] in {"COMPLETED", "FAILED"}:
                break
            await asyncio.sleep(0.5)
        assert record is not None and record["state"] == "COMPLETED", (
            f"exception did not reach COMPLETED in time: {record}"
        )

    after = _read_worker_metrics()
    assert after.returncode == 0, after.stdout + after.stderr
    after_le_5s = _sum_bucket_values(after.stdout, le="5.0")

    # The deterministic provider's configured latency is well under one second, so a
    # correctly unit-converted observation must land at or below the le="5.0" bucket. If
    # the duration were still recorded in milliseconds, this delta would stay at 0 and
    # the sample would only ever reach the +Inf bucket instead.
    delta = after_le_5s - before_le_5s
    assert delta == 1, (
        f"processing duration for the job just completed did not land in the <=5.0s "
        f'bucket (le="5.0" count changed by {delta}, expected 1) — looks like it\'s '
        "still being recorded in milliseconds instead of seconds"
    )

    # The real dashboard query must become finite after Prometheus scrapes the job.
    prometheus_port = host_port("COLDLINE_PROMETHEUS_HOST_PORT", 9090)
    query = (
        "histogram_quantile(0.95, sum by (le) "
        "(rate(coldline_exception_processing_duration_seconds_bucket[5m]))) "
        "and on() (sum(rate(coldline_exception_processing_duration_seconds_bucket"
        '{le="5.0"}[5m])) > 0)'
    )
    async with httpx.AsyncClient(timeout=5) as client:
        for _ in range(30):
            response = await client.get(
                f"http://localhost:{prometheus_port}/api/v1/query", params={"query": query}
            )
            response.raise_for_status()
            values = response.json()["data"]["result"]
            if values and math.isfinite(float(values[0]["value"][1])):
                assert 0 <= float(values[0]["value"][1]) <= 5
                break
            await asyncio.sleep(0.5)
        else:
            pytest.fail("Published p95 query did not produce a finite seconds value")
