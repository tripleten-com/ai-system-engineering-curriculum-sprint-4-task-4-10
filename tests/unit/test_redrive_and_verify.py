"""Coldline.

===================

File:              tests/unit/test_redrive_and_verify.py
Component:         Unit tests — Redrive and verify
Purpose:           Keep `poe redrive` recovering every dead-lettered message and reporting one.
Interacts With:    tests/failure/redrive_and_verify.py
Sprint/Task:       Sprint 4 — Project 4
Concepts:          Dead-letter redrive, idempotent recovery, evidence
Tools:             Python 3.12, pytest
"""

import json
from typing import Any

import pytest

from tests.failure import redrive_and_verify
from tests.security.fixtures import bearer_headers

MAIN_URL = "http://sqs.local/coldline-exception-jobs"
DLQ_URL = "http://sqs.local/coldline-exception-jobs-dlq"


def _body(exception_id: str) -> str:
    return json.dumps({"exception_id": exception_id, "job": "classify"})


class _FakeQueues:
    """A dead-letter queue and a main queue that a healthy worker drains at once."""

    def __init__(self, dead_lettered: list[tuple[str, int]]) -> None:
        self.dead_letter = [
            {"Body": _body(exception_id), "ReceiptHandle": f"rh-{index}", "sent": sent}
            for index, (exception_id, sent) in enumerate(dead_lettered)
        ]
        self.sent_to_main: list[str] = []
        self.receives = 0

    def get_queue_url(self, *, QueueName: str) -> dict[str, str]:
        return {"QueueUrl": DLQ_URL if QueueName.endswith("-dlq") else MAIN_URL}

    def receive_message(self, *, QueueUrl: str, MaxNumberOfMessages: int, **_: Any) -> Any:
        assert QueueUrl == DLQ_URL
        assert MaxNumberOfMessages <= 10
        self.receives += 1
        batch = self.dead_letter[:MaxNumberOfMessages]
        return {
            "Messages": [
                {
                    "Body": message["Body"],
                    "ReceiptHandle": message["ReceiptHandle"],
                    "Attributes": {"SentTimestamp": str(message["sent"])},
                }
                for message in batch
            ]
        }

    def send_message(self, *, QueueUrl: str, MessageBody: str) -> None:
        assert QueueUrl == MAIN_URL
        self.sent_to_main.append(json.loads(MessageBody)["exception_id"])

    def delete_message(self, *, QueueUrl: str, ReceiptHandle: str) -> None:
        assert QueueUrl == DLQ_URL
        self.dead_letter = [m for m in self.dead_letter if m["ReceiptHandle"] != ReceiptHandle]

    def get_queue_attributes(self, **_: Any) -> dict[str, dict[str, str]]:
        return {
            "Attributes": {
                "ApproximateNumberOfMessages": "0",
                "ApproximateNumberOfMessagesNotVisible": "0",
            }
        }


class _EndlessQueues(_FakeQueues):
    """A dead-letter queue that something keeps refilling as fast as it is drained."""

    def delete_message(self, *, QueueUrl: str, ReceiptHandle: str) -> None:
        assert QueueUrl == DLQ_URL


class _FakeResponse:
    def __init__(self, payload: dict[str, object] | None) -> None:
        self._payload = payload or {}
        self.status_code = 404 if payload is None else 200

    def raise_for_status(self) -> None:
        assert self.status_code == 200

    def json(self) -> dict[str, object]:
        return dict(self._payload)


def _install(
    monkeypatch: pytest.MonkeyPatch,
    queues: _FakeQueues,
    records: dict[str, dict[str, object]],
) -> None:
    """Point the script at the fake queues and a fake API reading `records`."""

    class _FakeApi:
        def __init__(self, **_: Any) -> None:
            pass

        def __enter__(self) -> "_FakeApi":
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def get(self, path: str, headers: dict[str, str] | None = None) -> _FakeResponse:
            # From Task 4.2 the summary route is protected: the script reads it as the
            # dispatcher, so every read must carry that bearer token.
            assert headers == bearer_headers("dispatcher-valid")
            # An id with no record is one the API no longer has: a 404.
            return _FakeResponse(records.get(path.rsplit("/", 1)[-1]))

    monkeypatch.setattr(redrive_and_verify, "client", lambda: queues)
    monkeypatch.setattr(redrive_and_verify.httpx, "Client", _FakeApi)
    monkeypatch.setattr(redrive_and_verify.time, "sleep", lambda _: None)


def _record(state: str = "COMPLETED") -> dict[str, object]:
    return {"state": state, "updated_at": "2026-01-01T00:00:01Z", "summary": "classified"}


def _run(capsys: pytest.CaptureFixture[str]) -> tuple[int, dict[str, Any]]:
    exit_code = redrive_and_verify.main()
    return exit_code, json.loads(capsys.readouterr().out)


def test_every_dead_lettered_message_is_redriven_and_the_newest_is_reported(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A stale message from another exercise is redriven too, not left behind."""
    queues = _FakeQueues([("exc-stale", 1_000), ("exc-injected", 2_000)])
    _install(monkeypatch, queues, {"exc-stale": _record(), "exc-injected": _record()})

    exit_code, output = _run(capsys)

    assert exit_code == 0
    assert queues.dead_letter == []
    assert output["exception_id"] == "exc-injected"
    assert output["also_redriven"] == ["exc-stale"]
    assert output["state"] == "COMPLETED"
    # Both redriven once, then only the reported exception delivered a second time.
    assert sorted(queues.sent_to_main[:2]) == ["exc-injected", "exc-stale"]
    assert queues.sent_to_main[2:] == ["exc-injected"]
    assert output["replay"] == {
        "deliveries_after_completion": 1,
        "consumed": True,
        "state": "COMPLETED",
        "updated_at_unchanged": True,
        "summary_unchanged": True,
    }


def test_a_single_message_keeps_the_existing_output(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The existing keys keep their meaning; `also_redriven` is simply empty."""
    queues = _FakeQueues([("exc-only", 1_000)])
    _install(monkeypatch, queues, {"exc-only": _record()})

    exit_code, output = _run(capsys)

    assert exit_code == 0
    assert list(output) == [
        "exception_id",
        "state",
        "summary",
        "replay",
        "also_redriven",
        "missing",
    ]
    assert output["exception_id"] == "exc-only"
    assert output["summary"] == "classified"
    assert output["also_redriven"] == []
    assert output["missing"] == []


def test_an_older_message_that_does_not_complete_fails_the_run(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Every redriven exception must complete, not only the reported one."""
    queues = _FakeQueues([("exc-stale", 1_000), ("exc-injected", 2_000)])
    _install(monkeypatch, queues, {"exc-stale": _record("FAILED"), "exc-injected": _record()})

    exit_code, output = _run(capsys)

    assert exit_code == 1
    assert output["exception_id"] == "exc-injected"
    assert output["replay"]["updated_at_unchanged"] is True


def test_a_replay_that_changes_the_record_fails_the_run(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The second delivery must leave the completed record exactly as it was."""
    queues = _FakeQueues([("exc-injected", 2_000)])
    records = {"exc-injected": _record()}
    _install(monkeypatch, queues, records)
    original_send = queues.send_message

    def send_and_reprocess(*, QueueUrl: str, MessageBody: str) -> None:
        original_send(QueueUrl=QueueUrl, MessageBody=MessageBody)
        if len(queues.sent_to_main) == 2:
            records["exc-injected"] = {**records["exc-injected"], "updated_at": "later"}

    monkeypatch.setattr(queues, "send_message", send_and_reprocess)

    exit_code, output = _run(capsys)

    assert exit_code == 1
    assert output["replay"]["updated_at_unchanged"] is False


def test_an_empty_dead_letter_queue_fails_with_a_hint(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Nothing to redrive is a failed exercise, not a pass."""
    _install(monkeypatch, _FakeQueues([]), {})

    assert redrive_and_verify.main() == 1
    assert "no dead-lettered message found" in capsys.readouterr().out


def test_more_than_one_batch_is_redriven_in_full(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A receive returns at most 10 messages; the loop keeps going until the queue is empty."""
    dead_lettered = [(f"exc-{index:02d}", 1_000 + index) for index in range(23)]
    queues = _FakeQueues(dead_lettered)
    _install(monkeypatch, queues, {exception_id: _record() for exception_id, _ in dead_lettered})

    exit_code, output = _run(capsys)

    assert exit_code == 0
    assert queues.dead_letter == []
    assert output["exception_id"] == "exc-22"
    assert output["also_redriven"] == [f"exc-{index:02d}" for index in range(21, -1, -1)]
    assert sorted(queues.sent_to_main[:23]) == sorted(
        exception_id for exception_id, _ in dead_lettered
    )


def test_the_newest_message_is_reported_whatever_order_it_arrives_in(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The reported exception is picked by SentTimestamp, not by receive order."""
    queues = _FakeQueues([("exc-injected", 3_000), ("exc-stale", 1_000), ("exc-middle", 2_000)])
    _install(
        monkeypatch,
        queues,
        {"exc-injected": _record(), "exc-stale": _record(), "exc-middle": _record()},
    )

    exit_code, output = _run(capsys)

    assert exit_code == 0
    assert output["exception_id"] == "exc-injected"
    assert output["also_redriven"] == ["exc-middle", "exc-stale"]


def test_duplicate_messages_for_one_exception_are_all_moved_but_reported_once(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Every message leaves the dead-letter queue; each exception id is listed once."""
    queues = _FakeQueues([("exc-stale", 1_000), ("exc-injected", 2_000), ("exc-stale", 1_500)])
    _install(monkeypatch, queues, {"exc-stale": _record(), "exc-injected": _record()})

    exit_code, output = _run(capsys)

    assert exit_code == 0
    assert queues.dead_letter == []
    assert sorted(queues.sent_to_main[:3]) == ["exc-injected", "exc-stale", "exc-stale"]
    assert output["exception_id"] == "exc-injected"
    assert output["also_redriven"] == ["exc-stale"]


def test_an_older_orphan_is_reported_missing_without_failing_the_run(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A dead-lettered message whose record was reset away is listed, not fatal."""
    queues = _FakeQueues([("exc-orphan", 1_000), ("exc-injected", 2_000)])
    _install(monkeypatch, queues, {"exc-injected": _record()})

    exit_code, output = _run(capsys)

    assert exit_code == 0
    assert output["exception_id"] == "exc-injected"
    assert output["also_redriven"] == ["exc-orphan"]
    assert output["missing"] == ["exc-orphan"]


def test_a_missing_reported_exception_fails_the_run(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The reported exception must exist and complete; a 404 is printed, then fails."""
    queues = _FakeQueues([("exc-stale", 1_000), ("exc-orphan", 2_000)])
    _install(monkeypatch, queues, {"exc-stale": _record()})

    exit_code, output = _run(capsys)

    assert exit_code == 1
    assert output["exception_id"] == "exc-orphan"
    assert output["state"] == "MISSING"
    assert output["replay"] is None
    assert output["missing"] == ["exc-orphan"]


def test_a_queue_that_never_empties_stops_at_the_cap_and_fails(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The receive loop is bounded, and hitting the bound is reported."""
    queues = _EndlessQueues([("exc-injected", 2_000)])
    _install(monkeypatch, queues, {"exc-injected": _record()})

    exit_code = redrive_and_verify.main()
    captured = capsys.readouterr()

    assert exit_code == 1
    assert queues.receives == redrive_and_verify.MAX_RECEIVE_BATCHES
    assert "still not empty" in captured.err
    assert json.loads(captured.out)["exception_id"] == "exc-injected"
