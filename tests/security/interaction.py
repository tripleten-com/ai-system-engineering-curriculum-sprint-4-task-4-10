"""Coldline.

===================

File:              tests/security/interaction.py
Component:         Security tooling — In-process interaction harness
Purpose:           Run one exception through the worker, with a named emulator response and an
                    optional supplied note, in this process, and read back everything the run
                    left: the record, the logs, the model request, the audit trail.
Interacts With:    src/worker/use_cases.py, src/worker/guardrail.py, src/common/audit.py,
                    src/common/redactor.py, src/adapters/model/deterministic.py,
                    src/adapters/model/request_log.py, src/api/routes.py,
                    infra/corpus/documents.jsonl, tests/fixtures/credentials/test-values.yaml,
                    tests/fixtures/pii/notes.yaml, tests/security/harness.py,
                    tests/security/pii.py, tests/security/trace.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          Deterministic negative tests, in-process worker, the four locations a detail
                    can reach, an emulator that checks no key in this process
Tools:             Python 3.12, httpx, OpenTelemetry

Task 4.5 carries this harness for the supplied Task 4.3 and 4.4 tests under
``tests/student/`` and for the inherited rows' replay of the emulator. The in-process
emulator is composed with a constant key and no key check (``HARNESS_PROVIDER_KEY``): the
provider-key check of Task 4.5 is the running worker's, read from the local secret store,
and nothing here reads ``src/worker/config.py``.

Task 4.5 runs the supplied redaction tests through this in-process harness. It does not
run the Task 4.4 mutation checks. The worker application, the redactor, the guardrail,
the audit sink, and the model emulator are the real ones; the exception store is the
harness's memory store, the procedure source returns the supplied planted procedure the
running stack retrieves for the scenario's reading, the audit store is in memory, the
emulator records each request it receives in memory, and the worker's log lines are
captured. The emulator runs with no latency, so a run takes milliseconds.

``InteractionHarness`` extends ``AccessHarness`` (the in-process API and the token fixtures)
with the Task 4.3 methods (``run_worker``, ``audit_trail``, ``audit_text``, ``secret_values``,
``queued_exception``) and, for Task 4.4:

- ``await run_worker(response, note=...)``: ``note`` is a supplied note id (``N-01``) that
  replaces the scenario reading's handling note for that run;
- ``worker_logs(exception_id)``: the log lines the worker emitted during that run;
- ``model_request(exception_id)``: the text of the request the emulator received;
- ``expected_summary(exception_id)``: the summary a worker that redacts as supplied stores
  for that run, computed from the emulator and the redactor without reading the record;
- ``pii_findings(exception_id, note=..., response=...)``: the marked values of that note
  and that response found in the four locations, as lines; an empty list is a clean scan;
- ``redact(text)``, ``note(note_id)``, ``marked_values(note=..., response=...)``: the
  supplied redactor, a supplied note's text, and the fixture's marked values.

When the assessed checks run a student file, each worker run (with its note), each
request, and each call of ``redact`` is recorded against the pytest case that made it
(``tests/security/trace.py``).

Module-level helpers serve the assessed rows and are not harness methods, so a student
file (which may import ``InteractionHarness`` alone) cannot reach them: ``replayed_answer``
and ``expected_summary`` compute what a correct run produces from the reading alone;
``place_record`` puts a record of any state into a harness's store; ``run_application`` is
what ``run_worker`` runs, with the worker class and the provider as parameters, so the
trusted observation (``tests/security/guardrail_observation.py``) can run the student's
worker with the provider's answers captured and the guardrail stood in for; and
``captured_log_findings`` runs the worker once with a supplied note and a supplied
response, with ``sys.stdout`` and ``sys.stderr`` redirected for the duration of the run,
and searches every log message any logger emitted during the run and everything the run
wrote to either stream for the marked values of both, not only the lines that name the
exception, which is the correlation ``poe pii-scan`` relies on and a raw copy of the note
or of the answer logged or printed without the id would escape.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable, Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from typing import Any, Protocol, cast
from uuid import uuid4

import yaml
from opentelemetry import trace as otel_trace
from opentelemetry.sdk.trace import TracerProvider

from adapters.model.deterministic import RESPONSES, DeterministicModelProvider
from adapters.model.request_log import MemoryModelRequestLog
from api.security.tokens import TokenVerifier
from common.audit import AuditRecord
from common.redactor import redact
from domain.chunking import chunk_document
from domain.contracts import (
    AccessLabel,
    Candidate,
    DocumentRecord,
    ExceptionJob,
    ExceptionRecord,
    ExceptionState,
    ModelAnswer,
    ModelRequest,
    SensorReading,
)
from ports import ModelProvider
from tests.security import pii, trace
from tests.security.harness import TASK_ROOT, AccessHarness
from worker.guardrail import REASON_CODES, REVIEW_MESSAGE, ValidatedSummary, validate_summary
from worker.procedures import EXCERPT_WORDS, ProcedureExcerpt, excerpt_from
from worker.use_cases import WorkerApplication

BASELINE_PATH = Path("tests/e2e/baseline-exception.json")
CORPUS_PATH = Path("infra/corpus/documents.jsonl")
CREDENTIALS_PATH = Path("tests/fixtures/credentials/test-values.yaml")
# The supplied procedure the running stack retrieves for the scenario's reading (an upper
# excursion in the procedure tenancy), and the one that carries the planted instruction.
PLANTED_DOCUMENT_ID = "playbook-thermal-excursion"
NOW = datetime(2026, 9, 1, tzinfo=UTC)
_TRACER = otel_trace.get_tracer(__name__)
# What the in-process observation searches, in the order it reports them: every captured
# log message, then what the run wrote to the two standard streams.
CAPTURED_LOCATIONS: tuple[str, ...] = ("worker logs", "worker stdout", "worker stderr")
# The constant key the in-process emulator is built with. No authenticator is composed
# here, so the value is checked by nothing; the running worker's key is the store's.
HARNESS_PROVIDER_KEY = "harness-key"


def planted_excerpt(root: Path = TASK_ROOT) -> ProcedureExcerpt:
    """Return the excerpt the worker sends for the scenario's reading: the planted procedure.

    The supplied corpus is read as the ingestion reads it and chunked as the data layer
    chunks it, and the first chunk is bounded as ``ProcedureLookup`` bounds the top-ranked
    candidate, so the excerpt here is the one the running worker sends.
    """
    for line in (root / CORPUS_PATH).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        document = DocumentRecord.model_validate(json.loads(line))
        if document.document_id != PLANTED_DOCUMENT_ID:
            continue
        first = chunk_document(document)[0]
        return excerpt_from(
            (
                Candidate(
                    chunk_id=first.chunk_id,
                    document_id=first.document_id,
                    rank=1,
                    score=1.0,
                    text=first.text,
                    access=AccessLabel(
                        tenant_id=first.access.tenant_id, access_tier=first.access.access_tier
                    ),
                    provenance_revision=first.provenance.revision,
                ),
            ),
            words=EXCERPT_WORDS,
        )
    raise ValueError(f"{CORPUS_PATH.as_posix()} holds no document {PLANTED_DOCUMENT_ID!r}")


def secret_values(root: Path = TASK_ROOT) -> tuple[str, ...]:
    """Return the supplied credential values, in file order."""
    document = yaml.safe_load((root / CREDENTIALS_PATH).read_text(encoding="utf-8"))
    values = document.get("values") if isinstance(document, dict) else None
    if not isinstance(values, dict) or not all(
        isinstance(name, str) and isinstance(value, str) and value for name, value in values.items()
    ):
        raise ValueError(f"{CREDENTIALS_PATH.as_posix()} must map names to values under `values:`")
    return tuple(values.values())


def scenario_reading(
    root: Path = TASK_ROOT, *, response: str, note: str | None = None
) -> SensorReading:
    """Return the scenario's reading with a fresh identity, the response, and the chosen note.

    ``note`` is a supplied note id; its text replaces the fixture's handling note. None
    keeps the fixture's own note.
    """
    fixture = json.loads((root / BASELINE_PATH).read_text(encoding="utf-8"))
    reading = dict(cast(dict[str, Any], fixture["reading"]))
    suffix = uuid4().hex[:12]
    reading["reading_id"] = f"reading-harness-{suffix}"
    reading["shipment_id"] = f"shipment-harness-{suffix}"
    reading["recorded_at"] = NOW.isoformat()
    reading["emulator_response"] = response
    if note is not None:
        reading["handling_note"] = pii.note_text(note, root)
    return SensorReading.model_validate(reading)


class WorkerLike(Protocol):
    """What ``run_application`` needs of a worker: ``process`` one delivery of one job."""

    async def process(self, job: ExceptionJob, *, delivery_count: int) -> object:
        """Process one delivery and return the disposition."""
        ...


class PlantedProcedures:
    """Return the planted procedure for every reading, as the running retrieval does."""

    def __init__(self, excerpt: ProcedureExcerpt) -> None:
        """Bind the source to the one excerpt it answers with."""
        self._excerpt = excerpt
        self.readings: list[SensorReading] = []

    async def find(self, reading: SensorReading) -> ProcedureExcerpt:
        """Record the reading and answer with the planted excerpt."""
        self.readings.append(reading)
        return self._excerpt


class _LogCapture(logging.Handler):
    """Keep every log message emitted while attached."""

    def __init__(self) -> None:
        """Start empty, at the lowest level."""
        super().__init__(level=logging.DEBUG)
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        """Keep the formatted message."""
        self.lines.append(record.getMessage())


@contextmanager
def captured_logs() -> Iterator[list[str]]:
    """Capture every log line emitted in this process while the block runs.

    The root logger is lowered to INFO for the duration when it sits above it (the
    default), because the worker's job line is an INFO record; the level is restored
    afterwards, and the handler removed.
    """
    root = logging.getLogger()
    handler = _LogCapture()
    previous = root.level
    root.addHandler(handler)
    if root.level == logging.NOTSET or root.level > logging.INFO:
        root.setLevel(logging.INFO)
    try:
        yield handler.lines
    finally:
        root.removeHandler(handler)
        root.setLevel(previous)


def _ensure_tracer_provider() -> None:
    """Install an SDK tracer provider once, so spans here carry real trace ids.

    Without a provider every span is non-recording and has no trace id; with one, the
    worker run and each in-process request get a trace id of their own, as they do in the
    running stack. A provider another module installed first is kept.
    """
    if isinstance(otel_trace.get_tracer_provider(), otel_trace.ProxyTracerProvider):
        otel_trace.set_tracer_provider(TracerProvider())


class InteractionHarness(AccessHarness):
    """One in-process worker and API over one memory store and one memory audit sink."""

    responses: tuple[str, ...] = RESPONSES
    review_message: str = REVIEW_MESSAGE
    reason_codes: tuple[str, ...] = REASON_CODES

    def __init__(
        self,
        root: Path = TASK_ROOT,
        *,
        token_verifier: TokenVerifier | None = None,
        trace_path: Path | None = None,
    ) -> None:
        """Build the API as ``AccessHarness`` does, and the worker's collaborators beside it."""
        _ensure_tracer_provider()
        super().__init__(root, token_verifier=token_verifier, trace_path=trace_path)
        self._planted = planted_excerpt(root)
        self._request_log = MemoryModelRequestLog()
        self._emulator = DeterministicModelProvider(
            latency_ms=0,
            provider_key=HARNESS_PROVIDER_KEY,
            request_log=self._request_log,
        )
        self._logs: dict[str, list[str]] = {}
        self._notes = pii.load_notes(root)

    async def run_worker(
        self, response: str = "valid", *, note: str | None = None
    ) -> ExceptionRecord:
        """Process one fresh exception once, with the named response and note, and return it.

        The reading is the scenario's, with a fresh identity each call and, when ``note``
        names a supplied note (``"N-01"``), that note as its handling note; the record
        starts ``QUEUED`` as the API leaves it, the worker's ``process`` runs once as the
        queue would run it (delivery count 1) inside a processing span of its own, and
        the record as the worker left it is returned. Everything the run left is in
        ``worker_logs``, ``model_request`` and ``audit_trail`` under
        ``record.exception_id``.
        """
        return await run_application(self, response, note=note)

    def queued_exception(self) -> str:
        """Create one exception that is still ``QUEUED``, with no outcome, and return its id."""
        reading = scenario_reading(self.root, response="valid")
        exception_id = f"exc-{uuid4().hex}"
        self.repository.records[exception_id] = ExceptionRecord(
            exception_id=exception_id,
            reading=reading,
            state=ExceptionState.QUEUED,
            accepted_at=NOW,
            updated_at=NOW,
        )
        return exception_id

    def audit_trail(self, exception_id: str) -> list[AuditRecord]:
        """Return the audit records of one exception, oldest first."""
        return self._audit_store.trail_now(exception_id)

    def audit_text(self, exception_id: str) -> str:
        """Return the audit records of one exception as text, one JSON line per record.

        Every field and value of every record is in this text, so a test can assert that
        a token, a header name, or a secret value is nowhere in the trail.
        """
        return "\n".join(record.rendered() for record in self.audit_trail(exception_id))

    def secret_values(self) -> tuple[str, ...]:
        """Return the supplied credential values no audit record may contain."""
        return secret_values(self.root)

    def worker_logs(self, exception_id: str) -> str:
        """Return the log lines the worker emitted while it processed one run, as one text."""
        return "\n".join(self._logs.get(exception_id, []))

    def model_request(self, exception_id: str) -> str:
        """Return the text of the request the emulator received for one run; "" when none."""
        return self._request_log.text_for(exception_id) or ""

    def expected_summary(self, exception_id: str) -> str | None:
        """Return the summary a worker that redacts as supplied stores for one run.

        Computed from the run's reading alone: the emulator is replayed over the request
        a correct worker sends (the note redacted), the answer is redacted, and the
        supplied guardrail's verdict decides between the validated summary and the output
        policy's fixed message. The record is not read.
        """
        record = self.repository.records.get(exception_id)
        if record is None:
            raise ValueError(f"no run with the exception id {exception_id!r}")
        return expected_summary(exception_id=exception_id, reading=record.reading, root=self.root)

    def redact(self, text: str) -> str:
        """Return the supplied redactor's output for one text, exactly as the worker gets it."""
        trace.record(self._trace, {"kind": "redact", "characters": len(text)})
        return redact(text)

    def note(self, note_id: str) -> str:
        """Return one supplied note's text, by its id in ``tests/fixtures/pii/notes.yaml``."""
        if note_id not in self._notes:
            raise ValueError(f"unknown note {note_id!r}; choose one of {', '.join(self._notes)}")
        return self._notes[note_id].text

    def marked_values(
        self, *, note: str | None = None, response: str | None = None
    ) -> tuple[str, ...]:
        """Return the values the fixture marks for one note and one supplied response."""
        marked = pii.marked_values(self._notes, note=note, response=response)
        return tuple(item.value for item in marked)

    def pii_findings(
        self, exception_id: str, *, note: str | None = None, response: str | None = None
    ) -> list[str]:
        """Return where the marked values of one note and one response reached in one run.

        One line per marked value found in a location (``worker logs``, ``model request``,
        ``audit records``, ``stored summary``); an empty list means none of them was found
        anywhere. Name the note the run was given, the response, or both.
        """
        if note is None and response is None:
            raise ValueError("name the note id, the response, or both: pii_findings(id, note=...)")
        record = self.repository.records.get(exception_id)
        values = pii.marked_values(self._notes, note=note, response=response)
        locations = {
            "worker logs": self.worker_logs(exception_id),
            "model request": self.model_request(exception_id),
            "audit records": pii.details_text(
                entry.details for entry in self.audit_trail(exception_id)
            ),
            "stored summary": (record.summary or "") if record is not None else "",
        }
        return pii.render(pii.findings(locations, values))


def rendered_trail(records: Sequence[AuditRecord]) -> str:
    """Render records as the harness renders them, for checks that hold a list already."""
    return "\n".join(record.rendered() for record in records)


async def run_application(
    harness: InteractionHarness,
    response: str,
    *,
    note: str | None = None,
    application_class: Callable[..., WorkerLike] = WorkerApplication,
    provider: ModelProvider | None = None,
) -> ExceptionRecord:
    """Process one fresh exception once through a worker built on the harness's collaborators.

    This is ``harness.run_worker(response, note=...)``: a fresh ``QUEUED`` record for the
    scenario's reading (with the supplied note when one is named), a worker over the
    harness's store, emulator (or the ``provider`` given, which the trusted observation
    uses to capture the answers), planted procedure and audit sink, one ``process`` call
    as the queue would make it (delivery count 1) inside a processing span, with the log
    lines captured, and the record as the worker left it. ``application_class`` is the
    student's ``WorkerApplication`` unless the observation passes the one it loaded.
    """
    if response not in RESPONSES:
        choices = ", ".join(RESPONSES)
        raise ValueError(f"unknown response {response!r}; choose one of {choices}")
    reading = scenario_reading(harness.root, response=response, note=note)
    exception_id = f"exc-{uuid4().hex}"
    harness.repository.records[exception_id] = ExceptionRecord(
        exception_id=exception_id,
        reading=reading,
        state=ExceptionState.QUEUED,
        accepted_at=NOW,
        updated_at=NOW,
    )
    application = application_class(
        harness.repository,
        harness._emulator if provider is None else provider,
        PlantedProcedures(harness._planted),
        audit=harness._audit,
        clock=lambda: NOW,
    )
    job = ExceptionJob(exception_id=exception_id, reading=reading, accepted_at=NOW)
    with (
        captured_logs() as lines,
        _TRACER.start_as_current_span(
            "coldline.process_exception",
            attributes={"coldline.exception_id": exception_id, "coldline.delivery_count": 1},
        ),
    ):
        disposition = await application.process(job, delivery_count=1)
    harness._logs[exception_id] = list(lines)
    value = getattr(disposition, "value", disposition)
    trace.record(
        harness._trace,
        {
            "kind": "worker",
            "response": response,
            "note": note,
            "exception_id": exception_id,
            "disposition": value if isinstance(value, str) else str(value),
        },
    )
    return harness.repository.records[exception_id]


async def captured_log_findings(
    *,
    note: str | None = None,
    response: str = "valid",
    root: Path = TASK_ROOT,
    application_class: Callable[..., WorkerLike] = WorkerApplication,
) -> list[str]:
    """Run the worker once with a note and a response; search every captured message and stream.

    The trusted in-process half of the N-01 row and of the pii-echo row. ``poe pii-scan``
    reads the worker container's log lines that name the exception, so a copy of the raw
    note logged without the exception id (``LOGGER.info("raw note=%s", ...)`` before the
    note redaction), or of the raw answer (``LOGGER.info("raw answer=%s", ...)`` before
    the answer redaction), escapes that correlation, and so does a copy printed instead
    of logged (``print(job.reading.handling_note, flush=True)``), which no log check sees
    at all. Here the run happens under ``captured_logs``, which keeps every message any
    logger emitted while ``process`` ran, whatever it names, and with ``sys.stdout`` and
    ``sys.stderr`` redirected into buffers of their own for the duration of the run; each
    marked value of the note and of the response (the ``pii-echo`` contact) is searched in
    all of the messages and in both streams (``CAPTURED_LOCATIONS``). One line per value
    found, by its location and label and never by the value; an empty list means neither
    a message nor a stream carried one. A note and a response with no marked value between
    them is an error, not a clean result. ``application_class`` is the student's worker
    unless a caller passes another.
    """
    harness = InteractionHarness(root)
    values = pii.marked_values(harness._notes, note=note, response=response)
    if not values:
        raise ValueError(
            f"note {note!r} and response {response!r} mark no value to search for; name a "
            "supplied note with marked values, the pii-echo response, or both"
        )
    stdout, stderr = StringIO(), StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        record = await run_application(
            harness, response, note=note, application_class=application_class
        )
    captured = {
        "worker logs": "\n".join(harness._logs.get(record.exception_id, [])),
        "worker stdout": stdout.getvalue(),
        "worker stderr": stderr.getvalue(),
    }
    return pii.render(pii.findings(captured, values, order=CAPTURED_LOCATIONS))


def correct_request(
    *, exception_id: str, reading: SensorReading, planted: ProcedureExcerpt
) -> ModelRequest:
    """Return the request a worker that redacts as supplied sends for one reading."""
    return ModelRequest(
        exception_id=exception_id,
        shipment_id=reading.shipment_id,
        temperature_c=reading.temperature_c,
        allowed_min_c=reading.allowed_min_c,
        allowed_max_c=reading.allowed_max_c,
        handling_note=redact(reading.handling_note),
        procedure_id=planted.document_id,
        procedure_excerpt=planted.text,
        emulator_response=reading.emulator_response,
    )


def replayed_answer(
    *, exception_id: str, reading: SensorReading, root: Path = TASK_ROOT
) -> ModelAnswer:
    """Return the raw answer the real emulator gives the request a correct worker sends.

    The request is built as ``WorkerApplication.process`` must build it from Task 4.4:
    the reading's fields, the handling note redacted by the supplied redactor, the planted
    procedure the running stack retrieves for the scenario's reading, and the reading's
    response selector. The emulator is deterministic, so this is the text the running
    worker received, and its digest and length are what the model-response event must
    carry. Nothing from any record or audit row is trusted on the way.
    """
    planted = planted_excerpt(root)
    provider = DeterministicModelProvider(latency_ms=0, provider_key=HARNESS_PROVIDER_KEY)
    request = correct_request(exception_id=exception_id, reading=reading, planted=planted)
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(provider.summarize(request))
    # Called from inside a running loop (an async student test): replay on a fresh
    # loop in a worker thread, so the caller's loop is never re-entered.
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, provider.summarize(request)).result()


def expected_summary(
    *, exception_id: str, reading: SensorReading, root: Path = TASK_ROOT
) -> str | None:
    """Return the summary a correct worker stores for one reading, from the replay alone.

    The replayed answer is redacted as the worker must redact it, and the supplied
    guardrail decides: the validated ``summary`` for an accepted answer, the output
    policy's fixed message for a rejected one.
    """
    answer = replayed_answer(exception_id=exception_id, reading=reading, root=root)
    verdict = validate_summary(redact(answer.text))
    if isinstance(verdict, ValidatedSummary):
        return verdict.summary
    return REVIEW_MESSAGE


def place_record(
    harness: InteractionHarness,
    state: ExceptionState,
    *,
    summary: str | None,
    rejection_reason: str | None = None,
) -> str:
    """Put one record of the given state and summary into the harness's store; return its id.

    A record in any of the six states, with or without a stored summary, exactly as the
    database could hold it, so a route's decision can be judged for every combination.
    """
    exception_id = f"exc-{uuid4().hex}"
    stored_outcome = summary is not None and state is ExceptionState.COMPLETED
    harness.repository.records[exception_id] = ExceptionRecord(
        exception_id=exception_id,
        reading=scenario_reading(harness.root, response="valid"),
        state=state,
        accepted_at=NOW,
        updated_at=NOW,
        summary=summary,
        handling_class="thermal_excursion" if stored_outcome else None,
        next_step="operational_review" if stored_outcome else None,
        rejection_reason=rejection_reason,
        failure_reason="model_provider_exhausted" if state is ExceptionState.FAILED else None,
    )
    return exception_id
