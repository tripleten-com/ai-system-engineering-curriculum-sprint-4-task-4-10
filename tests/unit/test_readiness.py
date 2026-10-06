"""Coldline.

===================

File:              tests/unit/test_readiness.py
Component:         Unit tests — Test Readiness
Purpose:           Tests for condition-based readiness checks.
Interacts With:    One isolated source responsibility
Sprint/Task:       Sprint 1 — Project 1
Concepts:          Fast feedback, failure paths, state invariants
Tools:             Python 3.12, pytest
"""

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

TASK_ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "coldline_ready", TASK_ROOT / "tests/smoke/readiness.py"
)
assert SPEC is not None and SPEC.loader is not None
READY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(READY)


class RefusingClient:
    """Refuse every request, as a port with nothing listening behind it does."""

    def __init__(self) -> None:
        """Initialize the call count."""
        self.calls = 0

    def get(self, endpoint: str) -> httpx.Response:
        """Raise a connection error on every call."""
        self.calls += 1
        raise httpx.ConnectError("connection refused")


class TransientClient:
    """Fail one request before returning a healthy response."""

    def __init__(self) -> None:
        """Initialize the call count."""
        self.calls = 0

    def get(self, endpoint: str) -> httpx.Response:
        """Return a response only after one transient transport failure."""
        self.calls += 1
        if self.calls == 1:
            raise httpx.ConnectError("transient reset")
        request = httpx.Request("GET", endpoint)
        return httpx.Response(200, request=request)


def test_readiness_retries_a_transient_transport_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A just-started endpoint may reset once without failing the ready contract."""
    client = TransientClient()
    monkeypatch.setattr(READY, "_no_containers_running", lambda: False)

    errors = READY._wait_for_endpoints(
        client,
        endpoints={"api": "http://example.test/health"},
        attempts=2,
        delay=0,
    )

    assert errors == {}
    assert client.calls == 2


def test_readiness_stops_waiting_when_no_container_is_running(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A student who never started the stack must get an answer, not a silent wait."""
    client = RefusingClient()
    monkeypatch.setattr(READY, "_no_containers_running", lambda: True)

    errors = READY._wait_for_endpoints(
        client,
        endpoints={"api": "http://example.test/health"},
        attempts=60,
        delay=0,
    )

    assert list(errors) == ["api"]
    assert client.calls == 1


def test_readiness_polls_every_endpoint_on_each_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A slow surface must not hide behind an earlier one that is still failing."""
    client = RefusingClient()
    monkeypatch.setattr(READY, "_no_containers_running", lambda: False)

    errors = READY._wait_for_endpoints(
        client,
        endpoints={"api": "http://a.test", "grafana": "http://b.test"},
        attempts=2,
        delay=0,
    )

    assert sorted(errors) == ["api", "grafana"]
    assert client.calls == 4


def test_readiness_runs_compose_from_the_task_root() -> None:
    """Keep Compose discovery explicit after the readiness module moves."""
    assert READY.ROOT == TASK_ROOT


def test_worker_readiness_requires_compose_health(monkeypatch: pytest.MonkeyPatch) -> None:
    """The public ready gate must reject a running but unhealthy worker."""
    result = SimpleNamespace(
        returncode=0,
        stdout='{"Service":"worker","State":"running","Health":"unhealthy"}\n',
        stderr="",
    )
    monkeypatch.setattr(READY.subprocess, "run", lambda *args, **kwargs: result)

    assert READY._worker_health_error(attempts=1, delay=0) == (
        "container state=running health=unhealthy"
    )
