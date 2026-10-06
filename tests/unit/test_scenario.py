"""Coldline.

===================

File:              tests/unit/test_scenario.py
Component:         Unit tests — Published scenario output
Purpose:           Verify singular current trace references in scenario output, and the supplied
                    note the scenario sends when asked for one.
Interacts With:    tests.e2e.scenario, tests/fixtures/pii/notes.yaml
Sprint/Task:       Sprint 4 — Project 4 / Task 4.4
Concepts:          Deterministic evidence shape, supplied inputs
Tools:             Python 3.12, pytest
"""

import json

import httpx
import pytest

from tests.e2e import scenario
from tests.security import pii


def _transport(joined: bool, posted: list[dict[str, object]]) -> httpx.MockTransport:
    """Answer the intake, the status poll, and the Jaeger lookups, recording the intake body."""

    def respond(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            posted.append(json.loads(request.content))
            return httpx.Response(202, json={"status_url": "/api/v1/exceptions/example"})
        if request.url.path == "/api/v1/exceptions/example":
            return httpx.Response(
                200, json={"exception_id": "exception-example", "state": "COMPLETED"}
            )
        assert request.url.path == "/api/traces"
        assert json.loads(request.url.params["tags"]) == {
            "coldline.exception_id": "exception-example"
        }
        service = request.url.params["service"]
        trace_id = "joined-trace" if joined else f"{service}-trace"
        return httpx.Response(
            200,
            json={
                "data": [
                    {"traceID": "older-trace", "spans": [{"startTime": 10}]},
                    {"traceID": trace_id, "spans": [{"startTime": 20}]},
                ]
            },
        )

    return httpx.MockTransport(respond)


@pytest.mark.parametrize("joined", [False, True], ids=["separate-traces", "joined-trace"])
def test_published_scenario_prints_one_api_and_one_worker_trace_id(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], joined: bool
) -> None:
    """The command reports current references both before and after telemetry repair."""
    real_client = httpx.Client
    posted: list[dict[str, object]] = []
    monkeypatch.setattr(
        scenario.httpx,
        "Client",
        lambda **kwargs: real_client(transport=_transport(joined, posted), **kwargs),
    )

    assert scenario.main() == 0

    output = json.loads(capsys.readouterr().out)
    assert output["state"] == "COMPLETED"
    assert output["response"] == "valid"
    assert output["note"] is None
    assert output["api_trace_id"] == ("joined-trace" if joined else "coldline-api-trace")
    assert output["worker_trace_id"] == ("joined-trace" if joined else "coldline-worker-trace")
    assert "api_trace_ids" not in output
    assert "worker_trace_ids" not in output
    [reading] = posted
    assert reading["emulator_response"] == "valid"
    assert "Priya" in str(reading["handling_note"])


def test_the_note_option_sends_the_supplied_note_in_place_of_the_readings_own(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """`--note N-01` puts the fixture's text in the reading; `--response` combines with it."""
    real_client = httpx.Client
    posted: list[dict[str, object]] = []
    monkeypatch.setattr(
        scenario.httpx,
        "Client",
        lambda **kwargs: real_client(transport=_transport(True, posted), **kwargs),
    )

    assert scenario.main(["--note", "N-01", "--response", "pii-echo"]) == 0

    output = json.loads(capsys.readouterr().out)
    assert output["note"] == "N-01"
    assert output["response"] == "pii-echo"
    [reading] = posted
    assert reading["handling_note"] == pii.note_text("N-01")
    assert reading["emulator_response"] == "pii-echo"
    assert str(reading["reading_id"]).startswith("reading-syn-pii-echo-")


def test_an_unknown_note_or_response_is_refused_by_the_parser() -> None:
    """The choices are the fixture's ids and the emulator's names; anything else exits 2."""
    with pytest.raises(SystemExit) as refused_note:
        scenario.main(["--note", "N-99"])
    assert refused_note.value.code == 2
    with pytest.raises(SystemExit) as refused_response:
        scenario.main(["--response", "surprise"])
    assert refused_response.value.code == 2


@pytest.mark.parametrize("reverse", [False, True])
def test_trace_lookup_selects_the_most_recent_matching_trace(reverse: bool) -> None:
    """Jaeger result ordering does not choose an older run's trace reference."""
    traces = [
        {"traceID": "older-trace", "spans": [{"startTime": 10}]},
        {"traceID": "newer-trace", "spans": [{"startTime": 5}, {"startTime": 20}]},
    ]
    if reverse:
        traces.reverse()
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"data": traces}))
    ) as client:
        assert scenario._wait_for_traces(client, "coldline-api", "example") == "newer-trace"
