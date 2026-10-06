"""Coldline.

===================

File:              tests/unit/security/test_seeds.py
Component:         Unit tests — The two supplied seeds
Purpose:           Prove the fake key matches the supplied Gitleaks rule and no committed value
                    does, that the seed files land at the supplied paths outside the student
                    files, and that this repository holds the key in no scannable form.
Interacts With:    tests/security/seeds.py, .gitleaks.toml, tests/security/suppression.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.6
Concepts:          A gate proven on a known-bad change, carried from Task 4.5
Tools:             Python 3.12, pytest
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from adapters.secrets import FIRST_VERSION_VALUE
from tests.contract.submission_validation import ALLOWED_PATHS
from tests.security import seeds, suppression

TASK_ROOT = Path(__file__).resolve().parents[3]


def test_the_fake_key_matches_the_supplied_rule_and_no_vendor_shape() -> None:
    """The seeded key is in the Coldline format and starts with no partner-pattern prefix."""
    assert seeds.matches_supplied_rule(seeds.FAKE_KEY)
    assert re.fullmatch(r"cpk_[A-Za-z0-9]{32}", seeds.FAKE_KEY)
    assert seeds.SUPPLIED_RULE_REGEX == suppression.SUPPLIED_RULE_REGEX
    assert seeds.SUPPLIED_RULE_ID == suppression.SUPPLIED_RULE_ID
    for prefix in ("ghp_", "AKIA", "sk-", "xox", "glpat-", "AIza"):
        assert not seeds.FAKE_KEY.startswith(prefix)


def test_the_committed_development_values_do_not_match_the_supplied_rule() -> None:
    """The opening literal and the LocalStack values are not findings under the supplied rule.

    Each match is computed first and only its outcome asserted, with a label: pytest
    renders the arguments of a call it rewrites, and the first is the first version's value.
    """
    for label, value in (
        ("the first version's value", FIRST_VERSION_VALUE),
        ("the LocalStack access key id", "localstack-development-key"),
        ("the LocalStack secret access key", "localstack-development-secret"),
        ("the PostgreSQL password", "coldline_local"),
    ):
        matched = seeds.matches_supplied_rule(value)
        assert not matched, f"{label} matches the supplied provider-key rule"


def test_this_repository_spells_the_key_in_no_scannable_form() -> None:
    """Neither the seed module nor the shipped configuration holds the key in one piece."""
    sources = ("tests/security/seeds.py", ".gitleaks.toml", "tests/unit/security/test_seeds.py")
    for relative in sources:
        text = (TASK_ROOT / relative).read_text(encoding="utf-8")
        assert not seeds.matches_supplied_rule(text), relative


def test_the_seeds_land_at_the_supplied_paths_outside_the_student_files(tmp_path: Path) -> None:
    """Each seed lands under security/seed/, which no student file or suppression may name."""
    secret = seeds.apply("secret", tmp_path)
    vulnerable = seeds.apply("vulnerable", tmp_path)

    assert secret == tmp_path / "security/seed/provider-key.txt"
    assert vulnerable == tmp_path / "security/seed/requirements.txt"
    assert seeds.matches_supplied_rule(secret.read_text(encoding="utf-8"))
    assert "pyyaml==5.3" in vulnerable.read_text(encoding="utf-8")
    for path in seeds.SEED_PATHS.values():
        assert path.as_posix() not in ALLOWED_PATHS
        assert path.as_posix().startswith("security/seed/")
    with pytest.raises(ValueError, match="unknown seed"):
        seeds.apply("other", tmp_path)


def test_the_command_writes_the_seed_and_says_what_to_do_next(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`poe seed-secret` and `poe seed-vulnerable` print the path and the branch instructions."""
    assert seeds.main(["secret", "--root", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "wrote security/seed/provider-key.txt" in out and "draft branch" in out
    assert seeds.FAKE_KEY not in out, "the command prints the path, not the key"

    assert seeds.main(["vulnerable", "--root", str(tmp_path)]) == 0
    assert "wrote security/seed/requirements.txt" in capsys.readouterr().out
    assert (tmp_path / "security/seed/requirements.txt").is_file()
