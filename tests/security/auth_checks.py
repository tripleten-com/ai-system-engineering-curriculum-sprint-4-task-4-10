"""Coldline.

===================

File:              tests/security/auth_checks.py
Component:         Security tooling — Auth checks
Purpose:           Send one request per token fixture to the running API's summary endpoint
                    and tabulate the answers.
Interacts With:    The running API and worker, tests/fixtures/tokens/fixtures.yaml,
                    tests/e2e/baseline-exception.json
Sprint/Task:       Sprint 4 — Project 4 / Task 4.2
Concepts:          401 versus 403, evidence for the pull request
Tools:             Python 3.12, httpx

``poe auth-checks`` creates one exception with a stored summary through the running stack
(the supplied out-of-range reading with a fresh identity, then a wait for the worker to
store its summary), requests it once per fixture with that fixture's bearer token, and
prints a Markdown table of fixture, status, and reason. The table is the evidence the
Task asks for in the pull request description.

This tool's wait reads the status URL as the dispatcher **on purpose**: when that read is
refused, the table shows the refusal for every fixture, which is the diagnosis the
student needs. The assessed rows in ``tests/contract/test_exception_access.py`` use
``tests/security/live_record.py`` instead, whose wait polls the database inside the
``postgres`` container and so cannot be refused by a wrong setting; the two create the
exception the same way and differ only in how they wait.
"""

from __future__ import annotations

import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import httpx

from tests.runtime_config import host_port
from tests.security.fixtures import FIXTURE_NAMES, bearer_headers
from tests.security.live_record import unique_reading

TASK_ROOT = Path(__file__).resolve().parents[2]
COMPLETION_WAIT_SECONDS = 20.0
TERMINAL_STATES = {"COMPLETED", "FAILED"}


def api_client() -> httpx.Client:
    """Return a client for the running API on the host, honouring the port override."""
    port = host_port("COLDLINE_API_HOST_PORT", 8000)
    return httpx.Client(base_url=f"http://localhost:{port}", timeout=10.0)


def create_completed_exception(
    client: httpx.Client, *, wait_seconds: float = COMPLETION_WAIT_SECONDS
) -> tuple[str, str | None]:
    """Submit one reading and wait for its summary; return the id and the last state seen.

    The wait reads the status URL with ``dispatcher-valid``. When that read is refused
    (a wrong ``config/auth.yaml``, or a rule that refuses the dispatcher), the state is
    returned as ``None`` and the table below shows the refusal for every fixture, which
    is the diagnosis the student needs; the exception still exists. This is the
    interactive tool's wait only: the assessed rows wait through
    ``live_record.create_stored_exception``, which no setting can refuse.
    """
    accepted = client.post("/api/v1/readings", json=unique_reading())
    accepted.raise_for_status()
    body = accepted.json()
    exception_id = cast(str, body["exception_id"])
    status_url = cast(str, body["status_url"])
    deadline = time.monotonic() + wait_seconds
    state: str | None = None
    while time.monotonic() < deadline:
        response = client.get(status_url, headers=bearer_headers("dispatcher-valid"))
        if response.status_code != 200:
            return exception_id, None
        state = cast(str, response.json()["state"])
        if state in TERMINAL_STATES:
            break
        time.sleep(0.5)
    return exception_id, state


def probe(client: httpx.Client, exception_id: str, fixture: str) -> tuple[int, str]:
    """Request one exception with one fixture; return the status and a one-line reason."""
    response = client.get(f"/api/v1/exceptions/{exception_id}", headers=bearer_headers(fixture))
    return response.status_code, reason_of(response)


def reason_of(response: httpx.Response) -> str:
    """Summarise one answer: the refusal's detail, or what a 200 returned."""
    try:
        body = response.json()
    except ValueError:
        body = None
    if response.status_code == 200 and isinstance(body, dict):
        return "summary returned" if body.get("summary") else "record returned, no summary stored"
    if isinstance(body, dict) and isinstance(body.get("detail"), str):
        return str(body["detail"])
    return response.text.strip()[:120] or response.reason_phrase


def table(rows: list[tuple[str, int, str]]) -> str:
    """Render the fixture, status, and reason rows as a Markdown table."""
    lines = ["| Fixture | Status | Reason |", "|---|---|---|"]
    lines.extend(f"| `{name}` | {status} | {reason} |" for name, status, reason in rows)
    return "\n".join(lines)


def main() -> int:
    """Create the exception, probe it with every fixture, and print the table."""
    try:
        with api_client() as client:
            exception_id, state = create_completed_exception(client)
            rows = [(name, *probe(client, exception_id, name)) for name in FIXTURE_NAMES]
    except httpx.HTTPError as exc:
        print(
            f"auth-checks: the API did not answer ({exc}); run `poe start` first",
            file=sys.stderr,
        )
        return 1
    print(f"exception_id: {exception_id}")
    print(
        f"state: {state}"
        if state is not None
        else "state: unknown (the dispatcher-valid read was refused; see its row)"
    )
    print(f"ran_at: {datetime.now(UTC).isoformat(timespec='seconds')}")
    print()
    print(table(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
