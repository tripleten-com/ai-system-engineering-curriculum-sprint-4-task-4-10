"""Coldline.

===================

File:              src/adapters/logging.py
Component:         Adapter — Logging
Purpose:           Configure bounded structured logging for Coldline services.
Interacts With:    Domain contracts, ports, and local providers
Sprint/Task:       Sprint 1 — Project 1
Concepts:          Boundary translation, deterministic infrastructure
Tools:             Python 3.12, OpenTelemetry
"""

import json
import logging
from datetime import UTC, datetime

from opentelemetry import trace

from domain.redaction import redact_sensitive_text


class JsonFormatter(logging.Formatter):
    """Render one redacted JSON log record with trace correlation."""

    def __init__(self, service_name: str) -> None:
        """Bind every formatted record to one stable telemetry identity."""
        super().__init__()
        self._service_name = service_name

    def format(self, record: logging.LogRecord) -> str:
        """Return one structured and redacted log line."""
        span_context = trace.get_current_span().get_span_context()
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "service": self._service_name,
            "level": record.levelname,
            "message": redact_sensitive_text(record.getMessage()),
        }
        if span_context.is_valid:
            payload["trace_id"] = format(span_context.trace_id, "032x")
            payload["span_id"] = format(span_context.span_id, "016x")
        if record.exc_info:
            payload["exception"] = redact_sensitive_text(self.formatException(record.exc_info))
        return json.dumps(payload, sort_keys=True)


def configure_json_logging(service_name: str) -> None:
    """Install one JSON handler for application and framework logs."""
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter(service_name))
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        framework_logger = logging.getLogger(name)
        framework_logger.handlers.clear()
        framework_logger.propagate = True
