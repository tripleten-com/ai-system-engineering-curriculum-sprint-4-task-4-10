"""Coldline.

===================

File:              src/adapters/model/request_log.py
Component:         Adapter — Model request log
Purpose:           Keep the text of each request the model emulator received, one record per
                    exception, so Task 4's `poe pii-scan` can read what the provider was sent.
Interacts With:    src/adapters/model/deterministic.py, src/worker/bootstrap.py,
                    src/worker/model_request.py, tests/security/interaction.py,
                    tests/security/pii_scan.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.4
Concepts:          Observable trust boundaries, tooling that stands in for a provider's own record
Tools:             Python 3.12

A hosted provider keeps its own record of every request it received, and that record is
where a leaked detail would sit, out of the sending system's reach. The emulator stands
in for that record here: when it is composed with a request log it writes the request
text, exactly as it received it, under the exception id, before it answers. The worker
container composes a ``FileModelRequestLog`` (``COLDLINE_MODEL_REQUEST_DIR`` in
``compose.yaml``) and ``python -m worker.model_request <exception_id>`` prints the record;
the in-process test harness composes a ``MemoryModelRequestLog``. This is tooling for the
Task's checks and for ``poe pii-scan``: it is not part of the audit trail, and nothing in
the application reads it back.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Protocol

from domain.contracts import ModelRequest

RECORD_SUFFIX = ".json"
# The identities the API mints (`exc-<hex>`) and the harness uses; anything else never
# becomes a file name.
_IDENTITY = re.compile(r"^[A-Za-z0-9_.:-]{1,120}$")


def request_text(request: ModelRequest) -> str:
    """Return the request as one JSON document with sorted keys: the text the provider got."""
    return json.dumps(request.model_dump(mode="json"), sort_keys=True, indent=2)


class ModelRequestLog(Protocol):
    """Keep the text of the request the emulator received for each exception."""

    def record(self, exception_id: str, text: str) -> None:
        """Keep one request's text under its exception id, replacing an earlier one."""
        ...

    def text_for(self, exception_id: str) -> str | None:
        """Return the recorded text for one exception, or None when none was recorded."""
        ...


def record_path(directory: Path, exception_id: str) -> Path:
    """Return the file one exception's record lives in, refusing an id that is not an id."""
    if not _IDENTITY.match(exception_id):
        raise ValueError(f"refusing to record a request under the id {exception_id!r}")
    return directory / f"{exception_id}{RECORD_SUFFIX}"


class FileModelRequestLog:
    """Write one file per exception under a directory inside the worker container."""

    def __init__(self, directory: Path) -> None:
        """Bind the log to its directory; it is created on the first record."""
        self._directory = directory

    @property
    def directory(self) -> Path:
        """Return the directory the records are written to."""
        return self._directory

    def record(self, exception_id: str, text: str) -> None:
        """Write the request text to the exception's file, replacing an earlier record."""
        path = record_path(self._directory, exception_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def text_for(self, exception_id: str) -> str | None:
        """Return the recorded text, or None when the exception has no record."""
        path = record_path(self._directory, exception_id)
        if not path.is_file():
            return None
        return path.read_text(encoding="utf-8")


class MemoryModelRequestLog:
    """Keep the records in a dictionary, for the in-process harness."""

    def __init__(self) -> None:
        """Start empty."""
        self.records: dict[str, str] = {}

    def record(self, exception_id: str, text: str) -> None:
        """Keep one request's text under its exception id."""
        record_path(Path("."), exception_id)
        self.records[exception_id] = text

    def text_for(self, exception_id: str) -> str | None:
        """Return the recorded text, or None."""
        return self.records.get(exception_id)
