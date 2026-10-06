"""Coldline.

===================

File:              src/domain/redaction.py
Component:         Domain — Redaction
Purpose:           Provide supplied redaction for bounded synthetic text fields.
Interacts With:    API and worker use cases
Sprint/Task:       Sprint 1 — Project 1
Concepts:          Business rules, immutable contracts, state
Tools:             Python 3.12
"""

import re

from domain.contracts import SensorReading

_PATTERNS = (
    re.compile(
        r"(?i)(name=)(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|"
        r"[^\s,;=\r\n]+(?:[ \t]+(?![A-Za-z_][\w.-]*=)[^\s,;=\r\n]+)?)"
    ),
    re.compile(r"(?i)(email=)([^\s]+)"),
    re.compile(r"(?i)(phone=)(\+?[0-9][0-9() .-]*?)(?=[ \t]+[A-Za-z_][\w.-]*=|[;\r\n]|$)"),
)


def redact_sensitive_text(value: str) -> str:
    """Replace common identifying values before logging or model use."""
    redacted = value
    for pattern in _PATTERNS:
        redacted = pattern.sub(r"\1[REDACTED]", redacted)
    return redacted


def redact_sensor_reading(reading: SensorReading) -> SensorReading:
    """Return a reading whose bounded free-text context is redacted."""
    return reading.model_copy(update={"context": redact_sensitive_text(reading.context)})
