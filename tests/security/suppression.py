"""Coldline.

===================

File:              tests/security/suppression.py
Component:         Security tooling — The one Gitleaks suppression
Purpose:           Read .gitleaks.toml and check that it is the supplied configuration plus
                    exactly one allowlist entry, scoped to one rule and the canonical pattern of
                    one path, with the required comment over it.
Interacts With:    .gitleaks.toml, docs/security/gate-policy.md, tests/security/scanners.py,
                    tests/contract/test_security_contract.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          A suppression as narrow as its finding, a written reason beside it, the
                    supplied configuration kept whole
Tools:             Python 3.12, tomllib

The student's one change to ``.gitleaks.toml`` is an allowlist entry, and the check reads
the file as what it must be: the supplied configuration, parsed, plus one top-level
``[[allowlists]]`` table and nothing else. The parsed document with its ``allowlists`` key
removed must equal the supplied document (``SUPPLIED_DOCUMENT``: the title, ``[extend]
useDefault = true`` and the supplied ``coldline-provider-key`` rule, which is what `poe
seed-secret`'s key is found by); a changed title, a disabled default rule, a second rule, a
changed keyword or any added key is a finding. The one entry must hold exactly
``targetRules`` (one element, the suppressed finding's rule) and ``paths`` (one element, the
canonical pattern of the finding's single path: ``^`` + ``re.escape(path)`` + ``$``, written
as a TOML literal string or as an equivalent escaped string; both parse to the same text),
and no other key: ``regexes``, ``stopwords``, ``commits``, ``condition``, ``regexTarget`` or
``description`` would widen or blur what the entry hides. An alternation, a wildcard, a
directory prefix or an unanchored path is refused by the same comparison: none of them is
the canonical pattern of one file. The comment lines directly over the entry's header must
name the finding id, give a date (``YYYY-MM-DD``), and say something beyond those two.

The ``[[rules]]`` plus ``[[rules.allowlists]]`` form Gitleaks also accepts is not accepted
here: it adds a rule table to the document, so the document is no longer the supplied one
plus an entry, and the one accepted form is what the gate policy documents.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

TASK_ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = Path(".gitleaks.toml")
SUPPLIED_TITLE = "Coldline secret-scanner configuration"
SUPPLIED_RULE_ID = "coldline-provider-key"
SUPPLIED_RULE_REGEX = r"\bcpk_[A-Za-z0-9]{32}\b"
# The supplied configuration as TOML parses it: the document the student's file must equal
# once its one `allowlists` entry is set aside. A change to the supplied file is a change
# here too, and the inventory configuration in tests/security/scanners.py carries the same
# extend table and rule (a unit test keeps the two in step).
SUPPLIED_DOCUMENT: dict[str, Any] = {
    "title": SUPPLIED_TITLE,
    "extend": {"useDefault": True},
    "rules": [
        {
            "id": SUPPLIED_RULE_ID,
            "description": "Coldline model-provider key",
            "regex": SUPPLIED_RULE_REGEX,
            "keywords": ["cpk_"],
        }
    ],
}
ENTRY_KEY = "allowlists"
REQUIRED_ENTRY_KEYS: frozenset[str] = frozenset({"targetRules", "paths"})
_DATE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
_FINDING_ID = re.compile(r"\bF-\d{2,3}\b")
_HEADER = re.compile(r"^\s*\[\[allowlists\]\]\s*(?:#.*)?$")
MINIMUM_REASON_WORDS = 3


class SuppressionError(ValueError):
    """Report that .gitleaks.toml cannot be read as a Gitleaks configuration."""


@dataclass(frozen=True)
class Entry:
    """One allowlist entry: the rules and paths it names, its other keys, and its comment."""

    rules: tuple[str, ...]
    paths: tuple[str, ...]
    other_keys: tuple[str, ...]
    comment: str
    line: int


def parse(text: str) -> dict[str, Any]:
    """Parse the configuration, or raise saying why it is not TOML."""
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise SuppressionError(f"{CONFIG_PATH.as_posix()} is not valid TOML: {exc}") from exc


def canonical_pattern(path: str) -> str:
    """Return the one pattern an entry may name for ``path``: anchored, every special escaped."""
    return "^" + re.escape(path) + "$"


def _strings(value: object) -> tuple[str, ...]:
    """Return a TOML array of strings as a tuple; anything else is empty."""
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return tuple(str(item) for item in value)
    return ()


def _comment_above(lines: list[str], index: int) -> str:
    """Return the comment lines directly above ``lines[index]``, joined, in order."""
    collected: list[str] = []
    position = index - 1
    while position >= 0 and lines[position].strip().startswith("#"):
        collected.insert(0, lines[position].strip().lstrip("#").strip())
        position -= 1
    return " ".join(collected)


def _headers(text: str) -> list[tuple[int, str]]:
    """Return the (line index, comment above) of each ``[[allowlists]]`` header, in order."""
    lines = text.splitlines()
    return [
        (index, _comment_above(lines, index))
        for index, raw in enumerate(lines)
        if _HEADER.match(raw)
    ]


def entries(text: str) -> list[Entry]:
    """Return every top-level allowlist entry the configuration holds, in file order."""
    document = parse(text)
    headers = _headers(text)
    result: list[Entry] = []
    top = document.get(ENTRY_KEY)
    if not isinstance(top, list):
        return result
    for position, item in enumerate(top):
        if not isinstance(item, dict):
            continue
        index, comment = headers[position] if position < len(headers) else (-1, "")
        result.append(
            Entry(
                _strings(item.get("targetRules")),
                _strings(item.get("paths")),
                tuple(sorted(set(item) - REQUIRED_ENTRY_KEYS)),
                comment,
                index + 1,
            )
        )
    return result


def supplied_config_findings(text: str) -> list[str]:
    """Return why the configuration, its allowlist entries set aside, is not the supplied one."""
    document = dict(parse(text))
    document.pop(ENTRY_KEY, None)
    if document == SUPPLIED_DOCUMENT:
        return []
    findings: list[str] = []
    for key in sorted(set(document) | set(SUPPLIED_DOCUMENT)):
        if key not in SUPPLIED_DOCUMENT:
            findings.append(
                f"{CONFIG_PATH.as_posix()} carries `{key}`, which the supplied configuration "
                "does not; the one change to this file is one allowlist entry"
            )
        elif key not in document:
            findings.append(
                f"{CONFIG_PATH.as_posix()} no longer carries `{key}`; keep the supplied "
                "configuration"
            )
        elif document[key] != SUPPLIED_DOCUMENT[key]:
            findings.append(
                f"{CONFIG_PATH.as_posix()}: `{key}` differs from the supplied configuration "
                "(the title, `[extend] useDefault = true` and the supplied "
                f"`{SUPPLIED_RULE_ID}` rule with its regex and keywords stay as supplied); the "
                "one change to this file is one allowlist entry"
            )
    return findings


def entry_findings(text: str, *, rule: str, path: str, finding_id: str) -> list[str]:
    """Return why the configuration does not suppress exactly the named finding, as required."""
    try:
        findings = supplied_config_findings(text)
        found = entries(text)
    except SuppressionError as exc:
        return [str(exc)]
    if not found:
        findings.append(
            f"{CONFIG_PATH.as_posix()} holds no `[[{ENTRY_KEY}]]` entry; add one for the "
            "finding you suppress, scoped to its rule and its single path, with the comment "
            "the gate policy describes"
        )
        return findings
    if len(found) > 1:
        findings.append(
            f"{CONFIG_PATH.as_posix()} holds {len(found)} allowlist entries; the Task's one "
            "suppression is one entry"
        )
        return findings
    [entry] = found
    if entry.rules != (rule,):
        named = ", ".join(entry.rules) or "no rule"
        findings.append(
            f"the entry at line {entry.line} names {named}; the suppressed finding "
            f"{finding_id}'s rule is `{rule}`, and `targetRules` must name exactly it"
        )
    expected = canonical_pattern(path)
    if len(entry.paths) != 1:
        findings.append(
            f"the entry at line {entry.line} names {len(entry.paths)} paths; `paths` must hold "
            f"the one pattern of {finding_id}'s single file"
        )
    elif entry.paths[0] != expected:
        findings.append(
            f"the entry's path pattern {entry.paths[0]!r} is not the pattern of {finding_id}'s "
            f"single file, {expected!r} (anchored with `^` and `$`, every special character "
            "escaped, no alternation, wildcard or directory); write it as a TOML literal "
            "string or as an equivalent escaped string"
        )
    if entry.other_keys:
        findings.append(
            f"the entry at line {entry.line} carries {', '.join(entry.other_keys)}; an entry "
            "holds `targetRules` and `paths` and nothing else"
        )
    comment = entry.comment
    if not comment:
        findings.append(
            f"the entry at line {entry.line} has no comment directly above it; add one that "
            "names the finding id, says why the match is safe, and gives the date you decided"
        )
    else:
        if finding_id not in _FINDING_ID.findall(comment):
            findings.append(
                f"the comment above the entry does not name the finding id {finding_id}"
            )
        if _DATE.search(comment) is None:
            findings.append("the comment above the entry gives no date (YYYY-MM-DD)")
        remainder = _DATE.sub("", _FINDING_ID.sub("", comment))
        if len(re.findall(r"[A-Za-z]{2,}", remainder)) < MINIMUM_REASON_WORDS:
            findings.append(
                "the comment above the entry says nothing about why the match is safe beyond "
                "the id and the date"
            )
    return findings


__all__ = [
    "CONFIG_PATH",
    "ENTRY_KEY",
    "REQUIRED_ENTRY_KEYS",
    "SUPPLIED_DOCUMENT",
    "SUPPLIED_RULE_ID",
    "SUPPLIED_RULE_REGEX",
    "SUPPLIED_TITLE",
    "Entry",
    "SuppressionError",
    "canonical_pattern",
    "entries",
    "entry_findings",
    "parse",
    "supplied_config_findings",
]
