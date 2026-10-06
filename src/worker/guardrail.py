"""Coldline.

===================

File:              src/worker/guardrail.py
Component:         Worker — Output guardrail
Purpose:           Validate a model provider's raw answer against the strict output schema and
                    return either the validated summary or a rejection with a reason code.
Interacts With:    schemas/exception-summary.schema.json, docs/security/output-policy.md,
                    src/worker/use_cases.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.3
Concepts:          Output validation at the point of storage, fail-safe rejection, closed
                    vocabularies, reason codes that never quote the answer
Tools:             Python 3.12, jsonschema

Supplied and settled: call it, do not edit it. ``validate_summary(raw)`` takes the provider's
raw answer text and returns one of two values:

- ``ValidatedSummary``: the answer parsed as JSON, checked against the whole schema, and
  carried as its five named fields. Nothing is stripped or repaired on the way: an answer
  with one extra field, one value outside a list, or one string over its bound is rejected
  whole.
- ``RejectedSummary``: a ``reason_code`` that names the schema rule the answer broke, and
  nothing from the answer itself. The codes are a closed list (``REASON_CODES``), each
  optionally suffixed with the schema field it applies to (``value_not_permitted:next_step``),
  so a stored reason can be read without the text that caused it.

``REVIEW_MESSAGE`` is the output policy's fixed dispatcher message, the one string a
``NEEDS_REVIEW`` record stores as its summary; ``docs/security/output-policy.md`` quotes it
verbatim.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "schemas/exception-summary.schema.json"
# The fixed message a dispatcher sees in place of a rejected answer. One string, stored as
# the record's summary on the NEEDS_REVIEW transition; the policy document quotes it.
REVIEW_MESSAGE = (
    "Automatic summary withheld: the model's answer did not pass the output check. "
    "A dispatcher must review this exception before anyone acts on it."
)
# The closed list of reason codes, in the order a rejection reports them when an answer
# breaks more than one rule: the first category present wins, so one answer always gives
# one code. A field suffix (`:next_step`) names the schema property, never the answer.
REASON_CODES: tuple[str, ...] = (
    "not_json",
    "not_an_object",
    "missing_property",
    "unknown_property",
    "wrong_type",
    "value_not_permitted",
    "too_short",
    "too_long",
)
_PRECEDENCE = {code: index for index, code in enumerate(REASON_CODES)}
# The schema keywords the validator can report, mapped to the code each one means.
_KEYWORD_CODES: dict[str, str] = {
    "required": "missing_property",
    "additionalProperties": "unknown_property",
    "type": "wrong_type",
    "enum": "value_not_permitted",
    "pattern": "value_not_permitted",
    "minLength": "too_short",
    "maxLength": "too_long",
}
# Keywords whose finding names a schema property; an unknown property's own name is answer
# text and is never carried, so `additionalProperties` reports no field.
_FIELD_KEYWORDS = frozenset({"type", "enum", "pattern", "minLength", "maxLength"})


@dataclass(frozen=True)
class ValidatedSummary:
    """The five schema fields of an answer that passed the whole schema."""

    summary: str
    handling_class: str
    next_step: str
    procedure_id: str | None
    response_id: str


@dataclass(frozen=True)
class RejectedSummary:
    """Why an answer was refused: the broken rule as a code, the schema field if any."""

    reason_code: str
    field: str | None = None

    @property
    def code(self) -> str:
        """Return the stored form: the code, with the schema field as a suffix when known."""
        return self.reason_code if self.field is None else f"{self.reason_code}:{self.field}"


@lru_cache(maxsize=1)
def load_schema(path: Path = SCHEMA_PATH) -> dict[str, Any]:
    """Return the supplied schema, read once, as the validator uses it."""
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"{path.name} must hold one JSON object")
    Draft202012Validator.check_schema(document)
    return document


def _reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build one JSON object from its members, refusing a key that appears twice.

    ``json.loads`` alone keeps the last of two members with one name and silently drops
    the other, which would let an invalid member disappear before the schema sees it.
    That is a repair, and the guardrail repairs nothing: the duplicate makes the text
    ``not_json``. The error names neither the key nor a value.
    """
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("a JSON object repeats a member name")
        document[key] = value
    return document


def validate_summary(
    raw: str, *, schema_path: Path = SCHEMA_PATH
) -> ValidatedSummary | RejectedSummary:
    """Check one raw answer against the output schema; never strip, repair, or quote it.

    Three stages, each a rejection on its own: the text must parse as JSON (with no
    object repeating a member name), the parsed value must be an object, and the object
    must satisfy every rule of the schema. When several rules are broken the reported
    code is the first in ``REASON_CODES`` among them, with ties on the field name, so
    the same answer always yields the same code.
    """
    try:
        document = json.loads(raw, object_pairs_hook=_reject_duplicate_members)
    except (TypeError, ValueError):
        return RejectedSummary("not_json")
    if not isinstance(document, dict):
        return RejectedSummary("not_an_object")
    schema = load_schema(schema_path)
    findings: list[tuple[int, str, str, str | None]] = []
    for error in Draft202012Validator(schema).iter_errors(document):
        keyword = str(error.validator)
        code = _KEYWORD_CODES.get(keyword, "value_not_permitted")
        field = str(error.path[0]) if error.path and keyword in _FIELD_KEYWORDS else None
        findings.append((_PRECEDENCE[code], field or "", code, field))
    if findings:
        findings.sort()
        _, _, code, field = findings[0]
        return RejectedSummary(code, field)
    procedure_id = document["procedure_id"]
    return ValidatedSummary(
        summary=str(document["summary"]),
        handling_class=str(document["handling_class"]),
        next_step=str(document["next_step"]),
        procedure_id=None if procedure_id is None else str(procedure_id),
        response_id=str(document["response_id"]),
    )
