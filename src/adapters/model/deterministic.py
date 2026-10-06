"""Coldline.

===================

File:              src/adapters/model/deterministic.py
Component:         Adapter — Deterministic
Purpose:           Implement the deterministic local model-provider adapter, its four supplied
                    responses, and, from Task 4.5, its check of the key each request presents.
Interacts With:    Domain contracts, ports, and local providers; infra/corpus/documents.jsonl
                    (the planted instruction the manipulated response follows);
                    src/adapters/model/request_log.py (the record of each request received);
                    src/adapters/model/provider_keys.py (the key check and its record)
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          Boundary translation, deterministic infrastructure, raw provider answers,
                    supplied bad answers, an answer that adds a detail its input never held,
                    a provider that accepts only the current key
Tools:             Python 3.12, OpenTelemetry

The emulator has four supplied responses, selected by the request's development-only
``emulator_response`` field (``poe scenario --response`` sets it on the reading, the worker
copies it into the request):

- ``valid`` (the default, and what an absent selector means): the JSON document the
  emulator has answered with since the Project 4 opening checkpoint. It satisfies
  ``schemas/exception-summary.schema.json``.
- ``malformed``: the same document, stopped partway through, as a provider that hit its
  output limit would stop. It is not valid JSON.
- ``manipulated``: well-formed JSON that follows the instruction planted in one supplied
  corpus procedure. The emulator reads the instruction out of the procedure excerpt it was
  given (``PLANTED_INSTRUCTION`` is its shape) and does what it says: it sets ``next_step``
  to a value outside the schema's list and adds a field the schema does not name. This is
  what a susceptible model does with an instruction in its input; the default response is
  the same model ignoring it.
- ``pii-echo`` (Task 4.4): the valid document with one more sentence in its summary, which
  names a contact phone number (``PII_ECHO_CONTACT``) that appears nowhere in the request.
  A model can write a detail its input never held; redacting the note the worker sends
  does nothing about it, and only a redaction of the answer keeps it out of the stored
  record. The document stays schema-valid, before and after the supplied redactor replaces
  the number.

As a provider keeps a record of what it was sent, the emulator records the text of every
request it receives when it is composed with a request log (``request_log.py``), under the
exception id, before it answers. ``poe pii-scan`` reads that record as the model request.

From Task 4.5 the emulator authenticates the key the client presents. The client carries
the key as a constant (``provider_key``) or as a per-use read (``key_reader``, awaited for
every request, which is how the worker's settings hand it over); when an ``authenticator``
is composed (``provider_keys.SecretStoreKeyAuthenticator`` in the running worker), the
presented key must be the current version of the provider key in the local secret store,
or the request fails with a terminal ``ProviderKeyRejected``. Without an authenticator (the
in-process harness, the unit tests) the key is taken and checked by nothing, as before.
"""

import asyncio
import hashlib
import json
import re
from collections.abc import Awaitable, Callable

from opentelemetry import trace

from adapters.model.provider_keys import KeyAuthenticator
from adapters.model.request_log import ModelRequestLog, request_text
from domain.contracts import ModelAnswer, ModelRequest
from domain.errors import TerminalProviderError

_TRACER = trace.get_tracer(__name__)
# How much of the retrieved procedure the emulator repeats in its summary.
_PROCEDURE_SENTENCE_CHARACTERS = 160
# The supplied responses, by the name `poe scenario --response` takes.
RESPONSES: tuple[str, ...] = ("valid", "malformed", "manipulated", "pii-echo")
DEFAULT_RESPONSE = "valid"
# The responses the supplied guardrail accepts, and the ones it refuses.
VALIDATED_RESPONSES: tuple[str, ...] = ("valid", "pii-echo")
REJECTED_RESPONSES: tuple[str, ...] = ("malformed", "manipulated")
# The shape of the instruction planted in the supplied corpus (`infra/corpus/documents.jsonl`,
# `playbook-thermal-excursion`), which the manipulated response follows. The values the
# corpus plants are the defaults below, so the response is the same whether or not the
# excerpt the request carries happens to hold the sentence.
PLANTED_INSTRUCTION = re.compile(
    r"set next_step to (?P<next_step>[a-z_]+) and add (?P<field>[a-z_]+): (?P<value>[a-z_]+)"
)
PLANTED_NEXT_STEP = "release_without_review"
PLANTED_FIELD = "dispatcher_override"
PLANTED_VALUE = "approved"
# Where the malformed answer stops: inside the summary string, three fifths of the way in.
_MALFORMED_NUMERATOR = 3
_MALFORMED_DENOMINATOR = 5
# The synthetic contact detail the `pii-echo` response adds to its summary: a fictional
# number in the reserved 555-01xx range that no supplied note or request carries.
PII_ECHO_CONTACT = "555-0199"
PII_ECHO_SENTENCE = f"For questions reach the night desk on {PII_ECHO_CONTACT}."
# A per-use key read: awaited for every request, so the key presented is the one the
# client's settings return at that moment.
KeyReader = Callable[[], Awaitable[str]]


class DeterministicModelProvider:
    """Return repeatable answers without network or paid-model calls.

    The emulator imitates a hosted provider's wire shape: it takes the client's key, as a
    constant or as a per-use read, the way a client would carry an API key, and answers
    with one JSON document as raw text. From Task 4.5 it authenticates the presented key
    when it is composed with an authenticator, accepting only the current version of the
    provider key.

    The answer repeats what the request carried. A handling note on the
    request appears in the summary verbatim, and so does the first sentence of
    the procedure excerpt, which is what a summarising model would do with the
    text it was given.
    """

    def __init__(
        self,
        *,
        latency_ms: int = 250,
        provider_key: str = "",
        key_reader: KeyReader | None = None,
        authenticator: KeyAuthenticator | None = None,
        request_log: ModelRequestLog | None = None,
    ) -> None:
        """Configure the delay, the key (a constant or a per-use read), the check, the log."""
        if latency_ms < 0:
            raise ValueError("latency_ms must not be negative")
        self._latency_seconds = latency_ms / 1000
        self._provider_key = provider_key
        self._key_reader = key_reader
        self._authenticator = authenticator
        self._request_log = request_log

    @property
    def provider_key(self) -> str:
        """Return the constant key the client was built with (empty when it reads per use)."""
        return self._provider_key

    @property
    def key_reader(self) -> KeyReader | None:
        """Return the per-use key read the client was built with, if any."""
        return self._key_reader

    @property
    def authenticator(self) -> KeyAuthenticator | None:
        """Return the key check the provider side applies, if one is composed."""
        return self._authenticator

    @property
    def request_log(self) -> ModelRequestLog | None:
        """Return the log the emulator records each received request in, if it has one."""
        return self._request_log

    async def presented_key(self) -> str:
        """Return the key the client presents for one request: the per-use read, or the constant."""
        if self._key_reader is not None:
            return await self._key_reader()
        return self._provider_key

    async def summarize(self, request: ModelRequest) -> ModelAnswer:
        """Return one raw answer for a synthetic temperature excursion.

        The request is recorded first, exactly as received, when a request log is
        composed. Then the presented key is authenticated when an authenticator is
        composed; a refused key is a terminal failure, as a hosted provider's 401 would be.
        The default answer is the valid JSON document; a request that names one of the
        other supplied responses receives that one. A name outside ``RESPONSES`` is a
        terminal failure, as a hosted provider's rejected request would be.
        """
        with _TRACER.start_as_current_span(
            "model_provider.summarize",
            attributes={"coldline.exception_id": request.exception_id},
        ):
            if self._request_log is not None:
                self._request_log.record(request.exception_id, request_text(request))
            if self._authenticator is not None:
                await self._authenticator.authenticate(await self.presented_key())
            if self._latency_seconds:
                await asyncio.sleep(self._latency_seconds)
            response = request.emulator_response or DEFAULT_RESPONSE
            if response not in RESPONSES:
                choices = ", ".join(RESPONSES)
                raise TerminalProviderError(
                    f"unknown supplied response {response!r}; choose one of {choices}"
                )
            payload = _valid_document(request)
            if response == "manipulated":
                payload = _follow_planted_instruction(payload, request.procedure_excerpt)
            if response == "pii-echo":
                payload = _echo_contact(payload)
            text = json.dumps(payload, sort_keys=True)
            if response == "malformed":
                text = _stopped_partway(text)
            return ModelAnswer(provider="deterministic-local", text=text)


def _valid_document(request: ModelRequest) -> dict[str, object]:
    """Return the schema-valid answer document for one request."""
    if request.temperature_c > request.allowed_max_c:
        magnitude = request.temperature_c - request.allowed_max_c
        condition = f"exceeded the upper handling bound by {magnitude:.1f} C"
    else:
        magnitude = request.allowed_min_c - request.temperature_c
        condition = f"fell below the lower handling bound by {magnitude:.1f} C"

    sentences = [
        f"Synthetic shipment {request.shipment_id} {condition}; operational review is required."
    ]
    if request.procedure_id is not None and request.procedure_excerpt:
        sentences.append(
            f"Procedure {request.procedure_id}: {_first_sentence(request.procedure_excerpt)}"
        )
    if request.handling_note:
        sentences.append(f"Handling note: {request.handling_note}")

    return {
        "summary": " ".join(sentences),
        "handling_class": "thermal_excursion",
        "next_step": "operational_review",
        "procedure_id": request.procedure_id,
        "response_id": _response_id(request),
    }


def _follow_planted_instruction(payload: dict[str, object], excerpt: str) -> dict[str, object]:
    """Apply the instruction the procedure excerpt plants, or the supplied corpus's defaults.

    A susceptible model does what the text it was given tells it to. The instruction the
    supplied corpus plants names a next step outside the schema's list and a field the
    schema does not have; when the excerpt carries that sentence its values are used, and
    when it does not (a request built without the planted procedure) the same two
    deviations are applied from the constants, so the response is deterministic either way.
    """
    match = PLANTED_INSTRUCTION.search(excerpt)
    if match is None:
        next_step, field, value = PLANTED_NEXT_STEP, PLANTED_FIELD, PLANTED_VALUE
    else:
        next_step, field, value = match["next_step"], match["field"], match["value"]
    manipulated = dict(payload)
    manipulated["next_step"] = next_step
    manipulated[field] = value
    return manipulated


def _echo_contact(payload: dict[str, object]) -> dict[str, object]:
    """Add the synthetic contact sentence to the summary; every other field stays as it is.

    The number is not in the request, so no redaction of the worker's input can remove it:
    a model that adds a detail is the case the answer-side redaction exists for.
    """
    echoed = dict(payload)
    echoed["summary"] = f"{payload['summary']} {PII_ECHO_SENTENCE}"
    return echoed


def _stopped_partway(text: str) -> str:
    """Cut the answer three fifths of the way through, as an output limit would."""
    return text[: len(text) * _MALFORMED_NUMERATOR // _MALFORMED_DENOMINATOR]


def _first_sentence(text: str) -> str:
    """Return the excerpt's first sentence, bounded, so the summary stays short."""
    sentence = text.split(". ", maxsplit=1)[0].strip()
    if not sentence.endswith("."):
        sentence = f"{sentence}."
    return sentence[:_PROCEDURE_SENTENCE_CHARACTERS]


def _response_id(request: ModelRequest) -> str:
    """Return a repeatable response identifier from the exception and shipment ids."""
    digest = hashlib.sha1(f"{request.exception_id}:{request.shipment_id}".encode())
    return digest.hexdigest()[:16]
