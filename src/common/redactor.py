"""Coldline.

===================

File:              src/common/redactor.py
Component:         Common — PII redactor
Purpose:           Replace the kinds of personal detail this redactor recognizes in free text
                    with a labeled placeholder, at one fixed version.
Interacts With:    src/worker/use_cases.py, docs/security/redactor.md,
                    tests/fixtures/pii/notes.yaml, tests/security/interaction.py,
                    tests/security/redaction_report.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.4
Concepts:          PII redaction before the first copy, labeled placeholders, deterministic text
                    rules, documented limitations
Tools:             Python 3.12, re

Supplied and settled: call it, do not edit it. ``redact(text)`` takes one string and returns
it with every phone number, email address and contact name it recognizes replaced by the
placeholder for that kind: ``[REDACTED:phone]``, ``[REDACTED:email]``, ``[REDACTED:name]``.
``redact(None)`` is ``None``, so a reading without a handling note needs no special case.
The result is stable: redacting an already redacted text changes nothing. Placeholders
contain no quote, backslash or line break. The supplied default and ``pii-echo`` fixtures
remain schema-valid after redaction. Other inputs can become invalid JSON or violate
schema constraints, so ``validate_summary`` must check the redacted answer.

What each kind means here, and what the redactor does not recognize, is written down in
``docs/security/redactor.md``, with one id per limitation. ``REDACTOR_VERSION`` names the
version that document describes; a Task that changes a rule changes the version too.
"""

from __future__ import annotations

import re
from typing import overload

REDACTOR_VERSION = "1.0.0"
# The kinds, in the order the rules are applied: an email address first (its local part can
# hold digits a phone rule would otherwise see), then phone numbers, then contact names.
KINDS: tuple[str, ...] = ("email", "phone", "name")
# A contact name is recognized by position only: one or two capitalized words directly after
# one of these cues (matched in any letter case).
NAME_CUES: tuple[str, ...] = ("call", "contact", "ask for", "notify", "reach", "page")
# A phone number is 7 to 15 digits, in the shapes the pattern below admits.
MINIMUM_PHONE_DIGITS = 7
MAXIMUM_PHONE_DIGITS = 15

_EMAIL = re.compile(
    r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?![\w-])"
)
# An optional `+` country code, an optional group in parentheses, then digit groups of two
# to four separated by one space, hyphen or period. The digit count is checked afterwards,
# so a short number (`8`, `12.5`) stays and a long one is replaced. The lookarounds keep a
# digit run inside a longer token (`shipment-syn-0123`, a hexadecimal id) out of the match.
_PHONE = re.compile(
    r"(?<![\w+.-])(?:\+\d{1,3}[ .-]?)?(?:\(\d{1,4}\)[ .-]?)?"
    r"\d{2,4}(?:[ .-]?\d{2,4}){0,4}(?![\w-])"
)
_CUES = "|".join(re.escape(cue) for cue in NAME_CUES)
_NAME = re.compile(r"\b(?i:" + _CUES + r")\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)")


def placeholder(kind: str) -> str:
    """Return the placeholder one recognized kind is replaced with."""
    if kind not in KINDS:
        raise ValueError(f"unknown redaction kind {kind!r}; choose one of {', '.join(KINDS)}")
    return f"[REDACTED:{kind}]"


def _phone(match: re.Match[str]) -> str:
    """Replace a digit run that has a phone number's digit count; leave a shorter one alone."""
    digits = sum(character.isdigit() for character in match.group(0))
    if MINIMUM_PHONE_DIGITS <= digits <= MAXIMUM_PHONE_DIGITS:
        return placeholder("phone")
    return match.group(0)


def _name(match: re.Match[str]) -> str:
    """Replace the name after a cue, keeping the cue and the space after it as written."""
    prefix = match.group(0)[: match.start(1) - match.start(0)]
    return f"{prefix}{placeholder('name')}"


@overload
def redact(text: str) -> str: ...


@overload
def redact(text: None) -> None: ...


def redact(text: str | None) -> str | None:
    """Return the text with every recognized phone number, email address and name replaced.

    ``None`` comes back as ``None``. The rules are applied in ``KINDS`` order and the
    result is idempotent: a placeholder matches none of the rules.
    """
    if text is None:
        return None
    redacted = _EMAIL.sub(placeholder("email"), text)
    redacted = _PHONE.sub(_phone, redacted)
    return _NAME.sub(_name, redacted)
