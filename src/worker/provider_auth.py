"""Coldline.

===================

File:              src/worker/provider_auth.py
Component:         Provider authentication record reader
Purpose:           Print which version of the provider key the worker last authenticated with,
                    from the record the model emulator keeps inside the worker container.
Interacts With:    src/adapters/model/provider_keys.py, src/worker/config.py,
                    pyproject.toml (`poe provider-auth-check`), tests/security/secret_tools.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          Evidence by version id and fingerprint, never by value
Tools:             Python 3.12

``poe provider-auth-check`` runs this inside the worker container, where the record is and
``COLDLINE_PROVIDER_AUTH_RECORD`` is set, the way ``poe model-request`` runs inside it. It
prints the version id and fingerprint of the key the worker last authenticated with, and,
when the most recent attempt was refused, that refusal and its reason. Nothing it prints is
a key value. ``--json`` prints the record as one JSON document for the checks. Exit 1 means
the worker has not authenticated with the provider yet in this container (run `poe
scenario` first); exit 2 means the worker keeps no record at all.
"""

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path

from adapters.model.provider_keys import AuthenticationOutcome, FileAuthenticationRecord
from worker.config import WorkerSettings


def render(accepted: AuthenticationOutcome, attempt: AuthenticationOutcome | None) -> list[str]:
    """Return the lines the check prints: the last accepted version, then a newer refusal."""
    lines = [
        "provider-auth-check: the worker last authenticated with version "
        f"{accepted.version_id} (fingerprint {accepted.fingerprint}) at {accepted.at}"
    ]
    if attempt is not None and not attempt.accepted and attempt.at >= accepted.at:
        lines.append(
            f"provider-auth-check: the most recent attempt, at {attempt.at}, was rejected: "
            f"{attempt.reason}"
        )
    return lines


def main(argv: Sequence[str] = (), *, record_path: str | None = None) -> int:
    """Print the record; ``record_path`` overrides the settings."""
    parser = argparse.ArgumentParser(
        description="Print the provider-key version the worker last authenticated with."
    )
    parser.add_argument("--json", action="store_true", help="print the record as JSON")
    arguments = parser.parse_args(list(argv))
    path = record_path
    if path is None:
        settings = WorkerSettings()  # type: ignore[call-arg]  # protected environment is the source
        path = settings.provider_auth_record
    if not path:
        print(
            "the worker keeps no authentication record: COLDLINE_PROVIDER_AUTH_RECORD is not set",
            file=sys.stderr,
        )
        return 2
    record = FileAuthenticationRecord(Path(path))
    accepted = record.last_accepted()
    attempt = record.last_attempt()
    if arguments.json:
        print(
            json.dumps(
                {
                    "last_accepted": None if accepted is None else asdict(accepted),
                    "last_attempt": None if attempt is None else asdict(attempt),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0 if accepted is not None else 1
    if accepted is None:
        if attempt is not None:
            print(
                "provider-auth-check: the worker has not been accepted by the provider in this "
                f"container; the most recent attempt, at {attempt.at}, was rejected: "
                f"{attempt.reason}",
                file=sys.stderr,
            )
        else:
            print(
                "provider-auth-check: the worker has not authenticated with the provider yet in "
                "this container; run `poe scenario` first",
                file=sys.stderr,
            )
        return 1
    for line in render(accepted, attempt):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
