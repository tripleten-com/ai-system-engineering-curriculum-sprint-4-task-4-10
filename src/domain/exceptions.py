"""Coldline.

===================

File:              src/domain/exceptions.py
Component:         Domain — Exceptions
Purpose:           Implement provider-neutral exception decisions.
Interacts With:    API and worker use cases
Sprint/Task:       Sprint 1 — Project 1
Concepts:          Business rules, immutable contracts, state
Tools:             Python 3.12
"""

from uuid import NAMESPACE_URL, uuid5

from domain.contracts import SensorReading


def requires_exception(reading: SensorReading) -> bool:
    """Return whether a reading falls outside its accepted handling range."""
    return not reading.allowed_min_c <= reading.temperature_c <= reading.allowed_max_c


def exception_id_for(reading: SensorReading) -> str:
    """Return a stable exception identity for idempotent reading replay."""
    return f"exc-{uuid5(NAMESPACE_URL, f'coldline:{reading.reading_id}')}"
