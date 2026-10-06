"""Coldline.

===================

File:              tests/unit/test_forcing_timing.py
Component:         Unit tests — Queue-forcing timing line
Purpose:           Keep the queue helpers' one-line timing record exact and always visible.
Interacts With:    tests/failure/forcing_timing.py, tests/failure/queue_client.py, tests/conftest.py
Sprint/Task:       Sprint 3 — Project 3
Concepts:          Fast feedback, evidence, dead-letter redrive, CI diagnostics
Tools:             Python 3.12, pytest
"""

import importlib.util
from pathlib import Path
from typing import Any

import pytest

from tests.failure import forcing_timing
from tests.failure.queue_client import exhaust_receive_budget

TESTS_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def isolated_collector(monkeypatch: pytest.MonkeyPatch) -> None:
    """Give every test its own collector state, whatever the session set up."""
    monkeypatch.setattr(forcing_timing, "_collected", None)


def test_the_line_has_the_fixed_shared_format() -> None:
    """The harness parses this exact shape; one decimal for seconds, a bare integer count."""
    line = forcing_timing.format_line(
        helper="trigger_alert_load",
        first_receive_seconds=0.04,
        receives_observed=4,
        deadline_seconds=40,
        outcome="dead_lettered",
    )

    assert line == (
        "queue-forcing helper=trigger_alert_load first_receive_seconds=0.0 receives_observed=4 "
        "deadline_seconds=40.0 outcome=dead_lettered"
    )
    assert forcing_timing.LINE_PATTERN.fullmatch(line)


@pytest.mark.parametrize(
    ("helper", "outcome"),
    [("force_dlq_arrival", "not_dead_lettered"), ("runtime_adapters", "received")],
)
def test_every_shared_helper_and_outcome_is_accepted(helper: str, outcome: str) -> None:
    """Each helper name and outcome in the shared contract formats and parses."""
    line = forcing_timing.format_line(
        helper=helper,
        first_receive_seconds=31.26,
        receives_observed=1,
        deadline_seconds=40.0,
        outcome=outcome,
    )
    assert f"helper={helper} " in line
    assert "first_receive_seconds=31.3 " in line
    assert line.endswith(f"outcome={outcome}")
    assert forcing_timing.LINE_PATTERN.fullmatch(line)


def test_an_unknown_helper_or_outcome_is_rejected() -> None:
    """The format is shared with the harness; neither side may drift it alone."""
    with pytest.raises(ValueError, match="helper"):
        forcing_timing.format_line(
            helper="something_else",
            first_receive_seconds=1.0,
            receives_observed=1,
            deadline_seconds=40.0,
            outcome="received",
        )
    with pytest.raises(ValueError, match="outcome"):
        forcing_timing.format_line(
            helper="force_dlq_arrival",
            first_receive_seconds=1.0,
            receives_observed=1,
            deadline_seconds=40.0,
            outcome="maybe",
        )


def test_a_forcing_that_never_saw_the_message_reports_the_deadline_it_waited_out() -> None:
    """No first receive: the line still carries a float, so the margin reads as zero."""
    line = forcing_timing.forcing_line(
        "force_dlq_arrival",
        {"receives_observed": 0, "first_receive_seconds": None, "deadline_seconds": 40.0},
        outcome="not_dead_lettered",
    )

    assert line == (
        "queue-forcing helper=force_dlq_arrival first_receive_seconds=40.0 receives_observed=0 "
        "deadline_seconds=40.0 outcome=not_dead_lettered"
    )


def test_outside_pytest_the_line_is_printed(capsys: pytest.CaptureFixture[str]) -> None:
    """A student's own `poe inject-failure` shows the line in its output."""
    forcing_timing.emit("queue-forcing helper=x")

    assert capsys.readouterr().out == "queue-forcing helper=x\n"


def test_under_pytest_the_line_is_collected_not_printed(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Captured output is hidden on a passing test, so the line waits for the summary."""
    forcing_timing.start_collecting()
    forcing_timing.emit("queue-forcing helper=x")

    assert capsys.readouterr().out == ""
    assert forcing_timing.collected() == ["queue-forcing helper=x"]


def test_relay_keeps_only_whole_timing_lines_from_a_subprocess_output() -> None:
    """A line quoted inside an assertion message is not a second record of the forcing."""
    forcing_timing.start_collecting()
    real = (
        "queue-forcing helper=runtime_adapters first_receive_seconds=0.1 receives_observed=1 "
        "deadline_seconds=40.0 outcome=received"
    )
    output = "\n".join(
        ["starting", real + "\r", f"E   {real}", "queue-forcing helper=broken", "done"]
    )

    forcing_timing.relay(output)

    assert forcing_timing.collected() == [real]


def test_without_timing_lines_removes_them_from_a_failure_message() -> None:
    """An assertion message quoting subprocess output must not repeat the line."""
    real = (
        "queue-forcing helper=runtime_adapters first_receive_seconds=0.1 receives_observed=1 "
        "deadline_seconds=40.0 outcome=received"
    )

    assert forcing_timing.without_timing_lines(f"a\n{real}\nb") == "a\nb"


def _load_conftest() -> Any:
    spec = importlib.util.spec_from_file_location("forcing_conftest", TESTS_ROOT / "conftest.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RecordingReporter:
    """Record what the terminal summary hook writes."""

    def __init__(self) -> None:
        """Start with no output."""
        self.lines: list[str] = []
        self.separators: list[str] = []

    def write_sep(self, sep: str, title: str) -> None:
        """Record a section separator."""
        self.separators.append(title)

    def write_line(self, line: str) -> None:
        """Record one written line."""
        self.lines.append(line)


def test_the_terminal_summary_prints_each_collected_line_once() -> None:
    """The hook is what puts a passing run's forcing into the CI job log."""
    conftest = _load_conftest()
    forcing_timing.start_collecting()
    forcing_timing.emit("queue-forcing helper=a")
    forcing_timing.emit("queue-forcing helper=b")
    reporter = RecordingReporter()

    conftest.pytest_terminal_summary(reporter)

    assert reporter.lines == ["queue-forcing helper=a", "queue-forcing helper=b"]
    assert len(reporter.separators) == 1


def test_the_terminal_summary_is_silent_when_nothing_was_forced() -> None:
    """Sessions that force nothing add nothing to the log."""
    conftest = _load_conftest()
    forcing_timing.start_collecting()
    reporter = RecordingReporter()

    conftest.pytest_terminal_summary(reporter)

    assert reporter.lines == [] and reporter.separators == []


class ScriptedSqs:
    """Answer receives from a script and count visibility changes."""

    def __init__(self, receives: list[bool], visibility_timeout: int = 30) -> None:
        """Script each receive as a message (True) or an empty answer (False)."""
        self.receives = list(receives)
        self.visibility_timeout = visibility_timeout
        self.count = 0

    def get_queue_attributes(self, **kwargs: Any) -> dict[str, Any]:
        """Return the queue's visibility timeout."""
        return {"Attributes": {"VisibilityTimeout": str(self.visibility_timeout)}}

    def receive_message(self, **kwargs: Any) -> dict[str, Any]:
        """Return the next scripted receive."""
        if self.receives and self.receives.pop(0):
            self.count += 1
            return {
                "Messages": [
                    {"ReceiptHandle": "h", "Attributes": {"ApproximateReceiveCount": self.count}}
                ]
            }
        return {}

    def change_message_visibility(self, **kwargs: Any) -> None:
        """Accept the visibility reset."""


def test_the_forcing_loop_reports_its_own_deadline_and_first_receive() -> None:
    """The success evidence carries the fields the timing line is built from."""
    forcing = exhaust_receive_budget(
        ScriptedSqs([True, True, True, True]), "url", max_receive_count=3
    )

    assert forcing["receives_observed"] == 4
    assert forcing["deadline_seconds"] == 40.0
    assert isinstance(forcing["first_receive_seconds"], float)


def test_a_timed_out_verifier_still_relays_the_line_it_printed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A forcing that ran past the container timeout is still recorded once."""
    import subprocess

    from tests.contract import test_runtime_adapters

    real = (
        "queue-forcing helper=runtime_adapters first_receive_seconds=40.3 receives_observed=0 "
        "deadline_seconds=40.0 outcome=not_dead_lettered"
    )

    def timed_out(*args: Any, **kwargs: Any) -> None:
        raise subprocess.TimeoutExpired("docker", 90, output=f"{real}\n".encode(), stderr=None)

    monkeypatch.setattr(test_runtime_adapters.subprocess, "run", timed_out)
    forcing_timing.start_collecting()

    with pytest.raises(subprocess.TimeoutExpired):
        test_runtime_adapters._run_verifier("print()")

    assert forcing_timing.collected() == [real]
