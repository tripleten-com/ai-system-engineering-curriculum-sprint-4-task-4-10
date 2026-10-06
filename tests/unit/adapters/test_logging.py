"""Coldline.

===================

File:              tests/unit/adapters/test_logging.py
Component:         Unit tests — Test Logging
Purpose:           Unit tests for bounded structured logging.
Interacts With:    One isolated source responsibility
Sprint/Task:       Sprint 1 — Project 1
Concepts:          Fast feedback, failure paths, state invariants
Tools:             Python 3.12, pytest
"""

import json
import logging
import sys

from adapters.logging import JsonFormatter, configure_json_logging


def test_json_log_includes_timestamp_and_redacted_exception() -> None:
    """Operational failures must retain time and traceback without leaking PII."""
    formatter = JsonFormatter("coldline-test")
    try:
        raise RuntimeError("email=ada@example.test provider failed")
    except RuntimeError:
        record = logging.LogRecord(
            name="coldline.test",
            level=logging.ERROR,
            pathname=__file__,
            lineno=1,
            msg="processing failed",
            args=(),
            exc_info=sys.exc_info(),
        )

    payload = json.loads(formatter.format(record))

    assert payload["timestamp"].endswith("+00:00")
    assert payload["service"] == "coldline-test"
    assert "RuntimeError" in payload["exception"]
    assert "ada@example.test" not in payload["exception"]


def test_json_log_redacts_pii_in_a_chained_multiline_traceback() -> None:
    """A traceback must not bypass the same redaction boundary as ordinary messages."""
    formatter = JsonFormatter("coldline-test")
    try:
        try:
            raise ValueError("carrier name=Ada Lovelace")
        except ValueError as cause:
            raise RuntimeError("delivery failed\ncontinuing") from cause
    except RuntimeError:
        record = logging.LogRecord(
            name="coldline.test",
            level=logging.ERROR,
            pathname=__file__,
            lineno=1,
            msg="processing name=Ada Lovelace\ncontinuing",
            args=(),
            exc_info=sys.exc_info(),
        )

    payload = json.loads(formatter.format(record))

    assert "Ada Lovelace" not in payload["message"]
    assert "Ada Lovelace" not in payload["exception"]
    assert "continuing" in payload["message"]


def test_uvicorn_logs_use_the_same_json_redaction_handler() -> None:
    """Framework access logs must not bypass the service logging boundary."""
    access = logging.getLogger("uvicorn.access")
    original_handlers = access.handlers[:]
    original_propagate = access.propagate
    try:
        access.addHandler(logging.StreamHandler())
        access.propagate = False

        configure_json_logging("coldline-test")

        assert access.handlers == []
        assert access.propagate is True
    finally:
        access.handlers = original_handlers
        access.propagate = original_propagate
