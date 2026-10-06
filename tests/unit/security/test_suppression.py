"""Coldline.

===================

File:              tests/unit/security/test_suppression.py
Component:         Unit tests — The one Gitleaks suppression
Purpose:           Prove the configuration reader accepts the supplied configuration plus one entry
                    scoped to one rule and the canonical pattern of one path with the required
                    comment, in either TOML string form, and names every way the entry is wider,
                    missing, doubled, uncommented, in another form, or the supplied part changed.
Interacts With:    tests/security/suppression.py, tests/security/scanners.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          A suppression as narrow as its finding, the supplied configuration kept whole
Tools:             Python 3.12, pytest

Every configuration here is synthetic text built over the supplied document; the shipped
.gitleaks.toml is student-editable and is not read. The rule and path names are invented.
"""

from __future__ import annotations

import pytest

from tests.security import scanners, suppression

SUPPLIED = (
    'title = "Coldline secret-scanner configuration"\n\n[extend]\nuseDefault = true\n\n'
    '[[rules]]\nid = "coldline-provider-key"\n'
    "description = \"Coldline model-provider key\"\nregex = '''\\bcpk_[A-Za-z0-9]{32}\\b'''\n"
    'keywords = ["cpk_"]\n'
)
RULE = "example-rule"
PATH = "fixtures/example/values.yaml"
COMMENT = (
    "\n# F-42: the matched values are synthetic example fixtures committed on purpose and\n"
    "# grant nothing anywhere. Decided 2026-10-05.\n"
)
LITERAL_PATHS = "paths = ['''^fixtures/example/values\\.yaml$''']\n"
ESCAPED_PATHS = 'paths = ["^fixtures/example/values\\\\.yaml$"]\n'
ENTRY = COMMENT + "[[allowlists]]\n" + f'targetRules = ["{RULE}"]\n' + LITERAL_PATHS


def _findings(text: str, **overrides: object) -> list[str]:
    arguments: dict[str, object] = {"rule": RULE, "path": PATH, "finding_id": "F-42"}
    arguments.update(overrides)
    return suppression.entry_findings(text, **arguments)  # type: ignore[arg-type]


def test_the_supplied_document_is_what_the_supplied_text_parses_to() -> None:
    """The constant the comparison uses is the supplied file's TOML, and the inventory agrees."""
    assert suppression.parse(SUPPLIED) == suppression.SUPPLIED_DOCUMENT
    inventory = suppression.parse(scanners.SUPPLIED_GITLEAKS_CONFIG)
    assert inventory["extend"] == suppression.SUPPLIED_DOCUMENT["extend"]
    assert inventory["rules"] == suppression.SUPPLIED_DOCUMENT["rules"]
    assert suppression.supplied_config_findings(SUPPLIED) == []


def test_a_scoped_commented_entry_in_either_string_form_passes() -> None:
    """One rule, the canonical anchored path, the id, the date and a reason: nothing to report."""
    assert _findings(SUPPLIED + ENTRY) == []
    escaped = SUPPLIED + ENTRY.replace(LITERAL_PATHS, ESCAPED_PATHS)
    assert _findings(escaped) == []
    [entry] = suppression.entries(SUPPLIED + ENTRY)
    assert entry.rules == (RULE,) and entry.paths == (suppression.canonical_pattern(PATH),)
    assert "F-42" in entry.comment and "2026-10-05" in entry.comment and entry.line > 0
    assert suppression.canonical_pattern(PATH) == "^fixtures/example/values\\.yaml$"


def test_the_rule_form_with_a_nested_allowlist_is_refused() -> None:
    """A `[[rules]]` table with `[[rules.allowlists]]` changes the supplied document."""
    text = SUPPLIED + (
        "\n# F-42: synthetic fixtures, not credentials. Decided 2026-10-05.\n"
        f'[[rules]]\nid = "{RULE}"\n'
        "[[rules.allowlists]]\n"
        "paths = ['''^fixtures/example/values\\.yaml$''']\n"
    )
    findings = _findings(text)
    assert any("`rules` differs from the supplied configuration" in f for f in findings)
    assert any("holds no `[[allowlists]]` entry" in f for f in findings)
    assert suppression.entries(text) == []


def test_no_entry_is_named_as_missing() -> None:
    """The supplied configuration alone holds no suppression."""
    findings = _findings(SUPPLIED)
    assert len(findings) == 1 and "holds no `[[allowlists]]` entry" in findings[0]


def test_two_entries_are_one_too_many() -> None:
    """The Task's suppression is one entry; a second is named."""
    findings = _findings(SUPPLIED + ENTRY + ENTRY)
    assert any("2 allowlist entries" in finding for finding in findings)


@pytest.mark.parametrize(
    "replacement, message",
    [
        ("", "names no rule"),
        (f'targetRules = ["{RULE}", "other-rule"]\n', "names example-rule, other-rule"),
        ('targetRules = ["other-rule"]\n', "names other-rule"),
    ],
    ids=["no-rule", "two-rules", "wrong-rule"],
)
def test_the_entry_must_name_exactly_the_findings_rule(replacement: str, message: str) -> None:
    """A path-only entry, two rules, or another rule is named."""
    text = SUPPLIED + ENTRY.replace(f'targetRules = ["{RULE}"]\n', replacement)
    findings = _findings(text)
    assert any(message in finding for finding in findings), findings


@pytest.mark.parametrize(
    "paths_line, message",
    [
        ("", "names 0 paths"),
        ("paths = ['''fixtures/''']\n", "is not the pattern of F-42's single file"),
        ("paths = ['''values''']\n", "is not the pattern of F-42's single file"),
        ("paths = ['''^fixtures/example/.*$''']\n", "is not the pattern"),
        ("paths = ['''fixtures/example/values\\.yaml''']\n", "is not the pattern"),
        ("paths = ['''^fixtures/example/values.yaml$''']\n", "is not the pattern"),
        (
            "paths = ['''^fixtures/example/values\\.yaml$|^future-secrets/''']\n",
            "is not the pattern",
        ),
        (
            "paths = ['''^fixtures/example/values\\.yaml$''', '''^src/app\\.py$''']\n",
            "names 2 paths",
        ),
        ("paths = ['''^src/app\\.py$''']\n", "is not the pattern of F-42's single file"),
        ("paths = ['''[unclosed''']\n", "is not the pattern"),
    ],
    ids=[
        "rule-only",
        "directory",
        "substring",
        "wildcard",
        "unanchored",
        "unescaped-dot",
        "alternation",
        "two-paths",
        "other-file",
        "invalid",
    ],
)
def test_the_entry_must_name_the_canonical_pattern_of_the_single_path(
    paths_line: str, message: str
) -> None:
    """Anything but `^` + re.escape(path) + `$` is refused: a directory, a wildcard, an alternation.

    The alternation `^<file>$|^future-secrets/` matches the one file today and every file
    under a directory that does not exist yet; checking it against the tree would pass it.
    """
    findings = _findings(SUPPLIED + ENTRY.replace(LITERAL_PATHS, paths_line))
    assert any(message in finding for finding in findings), findings


@pytest.mark.parametrize(
    "extra",
    [
        "regexes = ['''.*''']\n",
        "stopwords = ['''example''']\n",
        "commits = ['''abc''']\n",
        'regexTarget = "match"\n',
        'condition = "OR"\n',
        'description = "why"\n',
    ],
)
def test_keys_beyond_target_rules_and_paths_are_named(extra: str) -> None:
    """`regexes`, `stopwords`, `commits`, `regexTarget`, `condition`, `description`: all refused."""
    findings = _findings(SUPPLIED + ENTRY + extra)
    expected = "holds `targetRules` and `paths` and nothing else"
    assert any(expected in finding for finding in findings), findings


@pytest.mark.parametrize(
    "comment, message",
    [
        ("", "has no comment directly above it"),
        ("# Decided 2026-10-05, the fixtures are safe.\n", "does not name the finding id F-42"),
        ("# F-42: the fixtures are safe to keep here.\n", "gives no date"),
        ("# F-42 2026-10-05\n", "says nothing about why"),
        ("# F-42: safe. Decided 2026-10-05.\n\n", "has no comment directly above it"),
    ],
    ids=["none", "no-id", "no-date", "no-reason", "blank-line-between"],
)
def test_the_comment_must_sit_directly_above_and_carry_id_date_and_reason(
    comment: str, message: str
) -> None:
    """The comment lines directly over the header carry the id, a date and a reason."""
    header_and_body = ENTRY.split("[[allowlists]]", 1)[1]
    text = SUPPLIED + "\n" + comment + "[[allowlists]]" + header_and_body
    findings = _findings(text)
    assert any(message in finding for finding in findings), findings


@pytest.mark.parametrize(
    "change, message",
    [
        (("useDefault = true", "useDefault = false"), "`extend` differs"),
        (("[[rules]]\n", ""), "no longer carries `rules`"),
        (("{32}", "{8}"), "`rules` differs"),
        (('keywords = ["cpk_"]', 'keywords = ["cpk_", "key"]'), "`rules` differs"),
        (("Coldline secret-scanner configuration", "mine"), "`title` differs"),
        (("[extend]\n", '[extend]\npath = "other.toml"\n'), "`extend` differs"),
        (("[[rules]]\n", '[[rules]]\nid = "jwt"\nenabled = false\n[[rules]]\n'), "`rules` differs"),
        (("[extend]\n", "[allowlist]\npaths = ['''x''']\n[extend]\n"), "carries `allowlist`"),
    ],
    ids=[
        "default-rules-off",
        "rule-removed",
        "rule-regex",
        "rule-keywords",
        "title",
        "extend-path",
        "default-rule-disabled",
        "global-allowlist-table",
    ],
)
def test_any_change_to_the_supplied_part_is_named(change: tuple[str, str], message: str) -> None:
    """The document minus its entries must equal the supplied document, key for key.

    Disabling an unrelated default rule, a second extension setting, a changed keyword or
    an added table would leave the Task's entry valid and weaken what the gate finds later.
    """
    before, after = change
    text = (SUPPLIED + ENTRY).replace(before, after, 1)
    findings = _findings(text)
    assert any(message in finding for finding in findings), findings


def test_a_file_that_is_not_toml_is_one_finding() -> None:
    """A parse error is reported as a finding, not a traceback."""
    findings = _findings(SUPPLIED + "[[allowlists]\nbroken\n")
    assert len(findings) == 1 and "not valid TOML" in findings[0]
    with pytest.raises(suppression.SuppressionError):
        suppression.parse("= nope")
