"""Coldline.

===================

File:              src/api/audit_trail.py
Component:         Audit trail composition root
Purpose:           Print the ordered audit events of one exception from the audit_events table.
Interacts With:    PostgreSQL, src/common/audit.py, src/adapters/persistence/audit_store.py,
                    pyproject.toml (`poe audit-trail`)
Sprint/Task:       Sprint 4 — Project 4 / Task 4.3
Concepts:          Reconstructing one interaction from its audit records
Tools:             Python 3.12, PostgreSQL, asyncpg

``poe audit-trail <exception_id>`` runs this inside the API container, where the database
is reachable and ``COLDLINE_DATABASE_URL`` is set, the way ``poe ingest`` runs the corpus
ingestion. It prints every audit record of one exception, oldest first, each with its
event name, the exception id, the trace id of the request that recorded it, the time, and
the fields it carries. ``--json`` prints one JSON object per record instead, which is how
the assessed checks read the trail from the host.
"""

import argparse
import asyncio
import json
from collections.abc import Sequence

import asyncpg

from adapters.persistence import PostgresAuditStore
from api.config import ApiSettings
from common.audit import AuditRecord, AuditSink

COLUMNS = ("#", "event", "exception_id", "trace_id", "recorded_at", "details")


async def trail_for(exception_id: str) -> list[AuditRecord]:
    """Return the ordered audit records of one exception from the running database."""
    settings = ApiSettings()  # type: ignore[call-arg]  # values come from the protected environment
    pool = await asyncpg.create_pool(dsn=settings.database_url, min_size=1, max_size=2)
    if pool is None:  # pragma: no cover - asyncpg returns a pool or raises
        raise RuntimeError("could not create a PostgreSQL connection pool")
    try:
        return await AuditSink(PostgresAuditStore(pool)).trail(exception_id)
    finally:
        await pool.close()


def render_table(records: Sequence[AuditRecord]) -> str:
    """Render the records as a Markdown table, one row per event, in order."""
    lines = ["| " + " | ".join(COLUMNS) + " |", "|" + "---|" * len(COLUMNS)]
    for position, record in enumerate(records, start=1):
        details = json.dumps(record.details, sort_keys=True, default=str)
        lines.append(
            f"| {position} | `{record.event}` | `{record.exception_id}` | "
            f"`{record.trace_id or '-'}` | {record.recorded_at.isoformat()} | `{details}` |"
        )
    return "\n".join(lines)


def main(argv: Sequence[str] = ()) -> int:
    """Print one exception's audit trail; `--json` prints one JSON object per record."""
    parser = argparse.ArgumentParser(description="Print one exception's ordered audit events.")
    parser.add_argument("exception_id", help="the exception id `poe scenario` printed")
    parser.add_argument(
        "--json",
        action="store_true",
        help="print one JSON object per record instead of a table",
    )
    arguments = parser.parse_args(list(argv))
    records = asyncio.run(trail_for(arguments.exception_id))
    if arguments.json:
        for record in records:
            print(record.rendered())
        return 0
    if not records:
        print(f"no audit records for exception {arguments.exception_id}")
        return 1
    print(f"exception_id: {arguments.exception_id}")
    print(f"events: {len(records)}")
    print()
    print(render_table(records))
    return 0


if __name__ == "__main__":
    import sys

    raise SystemExit(main(sys.argv[1:]))
