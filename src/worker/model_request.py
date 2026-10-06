"""Coldline.

===================

File:              src/worker/model_request.py
Component:         Model request record reader
Purpose:           Print the text of the model request the emulator received for one exception,
                    from the request records the worker container keeps.
Interacts With:    src/adapters/model/request_log.py, src/worker/config.py,
                    pyproject.toml (`poe model-request`), tests/security/pii_scan.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.4
Concepts:          Reading what crossed a trust boundary, from the receiving side
Tools:             Python 3.12

``poe model-request <exception_id>`` runs this inside the worker container, where the
records are and ``COLDLINE_MODEL_REQUEST_DIR`` is set, the way ``poe audit-trail`` runs
inside the API container. It prints the one JSON document the emulator received for that
exception; ``poe pii-scan`` reads it the same way to search the model request for the
marked values. Exit 1 means no record exists for the id (the worker never processed it,
or it was processed before the container started); exit 2 means the worker records no
requests at all.
"""

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from adapters.model.request_log import FileModelRequestLog
from worker.config import WorkerSettings


def main(argv: Sequence[str] = (), *, request_dir: str | None = None) -> int:
    """Print one exception's recorded model request; ``request_dir`` overrides the settings."""
    parser = argparse.ArgumentParser(description="Print the model request one exception sent.")
    parser.add_argument("exception_id", help="the exception id `poe scenario` printed")
    arguments = parser.parse_args(list(argv))
    directory = request_dir
    if directory is None:
        settings = WorkerSettings()  # type: ignore[call-arg]  # protected environment is the source
        directory = settings.model_request_dir
    if not directory:
        print(
            "the worker records no model requests: COLDLINE_MODEL_REQUEST_DIR is not set",
            file=sys.stderr,
        )
        return 2
    try:
        text = FileModelRequestLog(Path(directory)).text_for(arguments.exception_id)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if text is None:
        print(f"no model request recorded for exception {arguments.exception_id}", file=sys.stderr)
        return 1
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
