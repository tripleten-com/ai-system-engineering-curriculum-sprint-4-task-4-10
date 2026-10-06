"""Coldline.

===================

File:              tests/unit/security/test_interaction.py
Component:         Unit tests — Interaction harness helpers
Purpose:           Prove the harness's supplied inputs are the running stack's (the planted
                    procedure, the scenario's reading, the supplied notes, the credential
                    values), that the replay a correct worker is compared with redacts the
                    note, and that the in-process log observation searches every captured
                    message for the note's and the response's marked values, not only the
                    lines that name the exception.
Interacts With:    tests/security/interaction.py, infra/corpus/documents.jsonl,
                    tests/fixtures/credentials/test-values.yaml, tests/fixtures/pii/notes.yaml,
                    tests/e2e/baseline-exception.json
Sprint/Task:       Sprint 4 — Project 4 / Task 4.4
Concepts:          Deterministic test inputs that match the live stack, expectations computed
                    without the record, evidence the live scan cannot correlate
Tools:             Python 3.12, pytest

The shipped ``src/worker/use_cases.py`` is never run here: it is the student's file, and
the assessed rows are where its outcomes are judged. The log observation is exercised
with probe workers written in this file (one logs the raw note before redacting it, one
logs the raw answer before redacting it, three print or write the raw note or the raw
answer to a standard stream instead, one does none of these), executed into modules of
their own.
"""

from __future__ import annotations

import logging
import sys
from datetime import UTC, datetime
from types import ModuleType

import pytest

from adapters.model.deterministic import PII_ECHO_CONTACT, PLANTED_INSTRUCTION
from common.audit import AuditRecord
from tests.security import interaction, pii
from worker.guardrail import REVIEW_MESSAGE
from worker.procedures import EXCERPT_WORDS

# A probe worker that redacts the note and the answer where the lesson says, with the
# worker's job line, and, when `LEAK` or `ANSWER_LEAK` is filled, one extra line before
# the note redaction or before the answer redaction: an INFO record that logs the raw
# note or the raw answer without the exception id (a line `poe pii-scan` cannot correlate
# with the run), or a `print` of it, or a write to `sys.stderr`, which no log check sees.
# Not the Task's worker: no retries, no audit events.
_PROBE_WORKER = '''"""Probe worker: redacts the note and the answer; may leak the raw note first."""

import logging
import sys

from common.redactor import redact
from domain.contracts import ExceptionState, ModelRequest
from worker.guardrail import validate_summary

LOGGER = logging.getLogger("worker.probe")


class WorkerApplication:
    """The smallest worker the harness can run."""

    def __init__(self, repository, provider, procedures, *, audit, clock, maximum_attempts=3):
        """Keep the collaborators the harness hands over."""
        self._repository = repository
        self._provider = provider
        self._procedures = procedures

    async def process(self, job, *, delivery_count):
        """Log the job, redact, call the provider, redact the answer, store it."""
{LEAK}        handling_note = redact(job.reading.handling_note)
        LOGGER.info(
            "reading job exception_id=%s handling_note=%s", job.exception_id, handling_note
        )
        await self._repository.transition(
            job.exception_id, {ExceptionState.QUEUED}, ExceptionState.PROCESSING
        )
        procedure = await self._procedures.find(job.reading)
        answer = await self._provider.summarize(
            ModelRequest(
                exception_id=job.exception_id,
                shipment_id=job.reading.shipment_id,
                temperature_c=job.reading.temperature_c,
                allowed_min_c=job.reading.allowed_min_c,
                allowed_max_c=job.reading.allowed_max_c,
                handling_note=handling_note,
                procedure_id=procedure.document_id,
                procedure_excerpt=procedure.text,
                emulator_response=job.reading.emulator_response,
            )
        )
{ANSWER_LEAK}        text = redact(answer.text)
        validate_summary(text)
        await self._repository.transition(
            job.exception_id, {ExceptionState.PROCESSING}, ExceptionState.COMPLETED,
            summary=text,
        )
        return "ACK"
'''
_LEAK_LINE = '        LOGGER.info("raw note=%s", job.reading.handling_note)\n'
_ANSWER_LEAK_LINE = '        LOGGER.info("raw answer=%s", answer.text)\n'
# The third review's shape: the raw note printed, with no log record and no exception id.
_PRINT_LINE = "        print(job.reading.handling_note, flush=True)\n"
_ANSWER_PRINT_LINE = "        print(answer.text, flush=True)\n"
_STDERR_LINE = '        sys.stderr.write(job.reading.handling_note + "\\n")\n'


def _build_probe(name: str, *, before_note: str = "", before_answer: str = "") -> type:
    """Execute the probe worker, with the given lines inserted, into a module of its own."""
    source = _PROBE_WORKER.replace("{LEAK}", before_note).replace("{ANSWER_LEAK}", before_answer)
    module = ModuleType(name)
    exec(compile(source, f"<{module.__name__}>", "exec"), module.__dict__)
    application: type = module.WorkerApplication
    return application


def _probe(leak: bool, *, answer_leak: bool = False) -> type:
    """Return the quiet probe, the one that logs the raw note, or the one that logs the answer."""
    name = "probe_quiet_worker"
    if leak:
        name = "probe_logging_worker"
    if answer_leak:
        name = "probe_answer_logging_worker"
    return _build_probe(
        name,
        before_note=_LEAK_LINE if leak else "",
        before_answer=_ANSWER_LEAK_LINE if answer_leak else "",
    )


def test_the_planted_excerpt_is_the_playbooks_first_chunk_with_the_instruction() -> None:
    """The excerpt names the playbook, is bounded as the lookup bounds it, and holds the plant."""
    excerpt = interaction.planted_excerpt()

    assert excerpt.found
    assert excerpt.document_id == interaction.PLANTED_DOCUMENT_ID
    assert excerpt.chunk_id == f"{interaction.PLANTED_DOCUMENT_ID}#0000"
    assert len(excerpt.text.split()) <= EXCERPT_WORDS
    assert excerpt.text.startswith("A thermal excursion begins")
    assert PLANTED_INSTRUCTION.search(excerpt.text) is not None
    assert excerpt.window_minutes is None


def test_the_scenario_reading_carries_a_fresh_identity_the_response_and_the_note() -> None:
    """Two readings differ in identity and share everything else; a note id swaps the note."""
    first = interaction.scenario_reading(response="malformed")
    second = interaction.scenario_reading(response="malformed")

    assert first.reading_id != second.reading_id
    assert first.shipment_id != second.shipment_id
    assert first.emulator_response == second.emulator_response == "malformed"
    assert first.temperature_c == 9.2 and first.allowed_max_c == 8.0
    assert first.handling_note == second.handling_note
    assert first.handling_note is not None and "Priya" in first.handling_note

    noted = interaction.scenario_reading(response="valid", note="N-01")
    assert noted.handling_note == pii.note_text("N-01")
    assert noted.emulator_response == "valid"


def test_the_credential_values_are_the_four_the_stack_holds() -> None:
    """The fixture lists the provider key, the two LocalStack keys, and the database password."""
    values = interaction.secret_values()

    assert values == (
        "coldline-dev-provider-key-v1",
        "localstack-development-key",
        "localstack-development-secret",
        "coldline_local",
    )


def test_the_replay_sends_the_redacted_note_and_the_expected_summary_follows_the_verdict() -> None:
    """The request a correct worker sends carries the redacted note; the summary is its echo.

    For the N-01 note the replayed answer carries placeholders and none of the marked
    values, the expected summary is the validated summary of the redacted answer, and for
    a refused response it is the output policy's fixed message. For pii-echo the contact
    the answer adds is redacted out of the expected summary.
    """
    notes = pii.load_notes()
    reading = interaction.scenario_reading(response="valid", note="N-01")
    request = interaction.correct_request(
        exception_id="exc-1", reading=reading, planted=interaction.planted_excerpt()
    )
    assert request.handling_note is not None
    for value in notes["N-01"].values:
        assert value not in request.handling_note
    assert "[REDACTED:email]" in request.handling_note

    answer = interaction.replayed_answer(exception_id="exc-1", reading=reading)
    for value in notes["N-01"].values:
        assert value not in answer.text
    summary = interaction.expected_summary(exception_id="exc-1", reading=reading)
    assert summary is not None
    assert summary.startswith("Synthetic shipment")
    assert "[REDACTED:phone]" in summary and "[REDACTED:email]" in summary

    refused = interaction.scenario_reading(response="malformed", note="N-01")
    assert interaction.expected_summary(exception_id="exc-2", reading=refused) == REVIEW_MESSAGE

    echo = interaction.scenario_reading(response="pii-echo")
    echoed = interaction.expected_summary(exception_id="exc-3", reading=echo)
    assert echoed is not None
    assert PII_ECHO_CONTACT not in echoed
    assert echoed.endswith("reach the night desk on [REDACTED:phone].")


def test_captured_logs_hold_the_info_lines_emitted_while_the_block_runs() -> None:
    """An INFO line from a worker logger is captured even when the root level sits above INFO."""
    root = logging.getLogger()
    previous = root.level
    root.setLevel(logging.WARNING)
    try:
        with interaction.captured_logs() as lines:
            logging.getLogger("worker.probe").info("reading job exception_id=%s", "exc-9")
        assert "reading job exception_id=exc-9" in lines
        assert root.level == logging.WARNING
    finally:
        root.setLevel(previous)


async def test_a_raw_note_logged_without_the_exception_id_is_found_in_every_message() -> None:
    """The probe that logs the raw note first is named; the one that does not is clean.

    The leaking line carries no exception id, so the live scan's correlation (the lines
    naming the exception) sees only the redacted job line and would call the logs clean;
    the in-process observation searches every captured message and finds both values.
    """
    notes = pii.load_notes()
    marked = notes[pii.FIRST_NOTE].marked
    values = notes[pii.FIRST_NOTE].values

    leaking = _probe(leak=True)
    found = await interaction.captured_log_findings(note=pii.FIRST_NOTE, application_class=leaking)
    assert found == [f"worker logs: {item.label}" for item in marked]
    # The finding names the label and the location, never the value it found.
    for value in values:
        assert not any(value in line for line in found), found

    # What the live correlation would have seen: the job line names the exception and is
    # clean; the leaking line names no exception, so a scan over correlated lines misses it.
    harness = interaction.InteractionHarness()
    record = await interaction.run_application(
        harness, "valid", note=pii.FIRST_NOTE, application_class=leaking
    )
    lines = harness.worker_logs(record.exception_id).splitlines()
    correlated = [line for line in lines if record.exception_id in line]
    assert correlated and all(value not in line for line in correlated for value in values)
    assert any(line.startswith("raw note=") for line in lines)

    quiet = _probe(leak=False)
    clean = await interaction.captured_log_findings(note=pii.FIRST_NOTE, application_class=quiet)
    assert clean == []


async def test_a_raw_answer_logged_before_the_redaction_is_found_by_the_echo_contact() -> None:
    """The probe that logs the raw answer first is named by the pii-echo contact; the quiet one not.

    The answer carries no exception id, and the note was redacted before the request, so
    the N-01 values are nowhere in the run: only the contact the `pii-echo` answer adds
    names the leak, and only because the observation selects marked values by the note
    and the response together. The live scan's correlated lines would have been clean.
    """
    notes = pii.load_notes()
    contact = pii.response_values("pii-echo")
    assert len(contact) == 1

    leaking = _probe(leak=False, answer_leak=True)
    found = await interaction.captured_log_findings(
        note=pii.FIRST_NOTE, response="pii-echo", application_class=leaking
    )
    assert found == [f"worker logs: {contact[0].label}"]
    assert contact[0].value not in found[0]

    # The same run, read two other ways: selecting by the note alone would have called it
    # clean (the note was redacted before the request, so the answer carries placeholders),
    # and so would the live correlation (the leaking line names no exception).
    harness = interaction.InteractionHarness()
    record = await interaction.run_application(
        harness, "pii-echo", note=pii.FIRST_NOTE, application_class=leaking
    )
    lines = harness.worker_logs(record.exception_id).splitlines()
    assert any(line.startswith("raw answer=") and contact[0].value in line for line in lines)
    assert pii.findings({"worker logs": "\n".join(lines)}, notes[pii.FIRST_NOTE].marked) == []
    correlated = "\n".join(line for line in lines if record.exception_id in line)
    assert correlated
    both = [*notes[pii.FIRST_NOTE].marked, *contact]
    assert pii.findings({"worker logs": correlated}, both) == []

    quiet = _probe(leak=False)
    clean = await interaction.captured_log_findings(
        note=pii.FIRST_NOTE, response="pii-echo", application_class=quiet
    )
    assert clean == []
    with pytest.raises(ValueError, match="mark no value"):
        await interaction.captured_log_findings(response="valid", application_class=quiet)


async def test_a_raw_note_printed_before_the_redaction_is_found_in_the_captured_stdout() -> None:
    """The third review's probe: `print(job.reading.handling_note, flush=True)`, then redaction.

    No log record carries the note, so both log checks (the live correlation and the
    captured messages) are clean; the observation redirects the standard streams for the
    run and finds both values in what the run printed, by label and location only.
    """
    notes = pii.load_notes()
    marked = notes[pii.FIRST_NOTE].marked
    original_stdout, original_stderr = sys.stdout, sys.stderr

    printing = _build_probe("probe_printing_worker", before_note=_PRINT_LINE)
    found = await interaction.captured_log_findings(note=pii.FIRST_NOTE, application_class=printing)
    assert found == [f"worker stdout: {item.label}" for item in marked]
    for value in notes[pii.FIRST_NOTE].values:
        assert not any(value in line for line in found), found
    assert sys.stdout is original_stdout and sys.stderr is original_stderr

    # The captured log messages of the same probe are clean: a log check alone misses it.
    harness = interaction.InteractionHarness()
    record = await interaction.run_application(
        harness, "valid", note=pii.FIRST_NOTE, application_class=printing
    )
    assert pii.findings({"worker logs": harness.worker_logs(record.exception_id)}, marked) == []

    writing = _build_probe("probe_stderr_worker", before_note=_STDERR_LINE)
    found = await interaction.captured_log_findings(note=pii.FIRST_NOTE, application_class=writing)
    assert found == [f"worker stderr: {item.label}" for item in marked]
    assert interaction.CAPTURED_LOCATIONS == ("worker logs", "worker stdout", "worker stderr")


async def test_a_raw_answer_printed_before_the_redaction_is_found_by_the_echo_contact() -> None:
    """`print(answer.text, flush=True)` before the answer redaction is named by the contact."""
    contact = pii.response_values("pii-echo")
    printing = _build_probe("probe_answer_printing_worker", before_answer=_ANSWER_PRINT_LINE)

    found = await interaction.captured_log_findings(
        note=pii.FIRST_NOTE, response="pii-echo", application_class=printing
    )

    assert found == [f"worker stdout: {contact[0].label}"]
    assert contact[0].value not in found[0]
    quiet = _probe(leak=False)
    clean = await interaction.captured_log_findings(
        note=pii.FIRST_NOTE, response="pii-echo", application_class=quiet
    )
    assert clean == []


def test_rendered_trail_joins_one_json_line_per_record() -> None:
    """The text a credential test searches is every record, one line each."""
    now = datetime(2026, 9, 1, tzinfo=UTC)
    records = [
        AuditRecord("a", "exc-1", None, now, {"k": "v"}, 1),
        AuditRecord("b", "exc-1", None, now, {}, 2),
    ]

    text = interaction.rendered_trail(records)

    assert text.count("\n") == 1
    assert '"event": "a"' in text and '"event": "b"' in text and '"k": "v"' in text
