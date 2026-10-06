"""Coldline.

===================

File:              tests/unit/security/test_repository.py
Component:         Unit tests — The checkout's Git history
Purpose:           Prove the helpers measure a checkout against its merge base with main, export
                    the starting checkpoint, list the files the gate scans, and answer nothing for
                    a nested or absent repository.
Interacts With:    tests/security/repository.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          The merge base as the starting checkpoint
Tools:             Python 3.12, pytest, Git
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tests.security import repository

GIT_IDENTITY = ("-c", "user.name=Repository Test", "-c", "user.email=repo@localhost")


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *GIT_IDENTITY, *arguments], cwd=root, check=True, capture_output=True, text=True
    )
    return completed.stdout.strip()


def _repository(tmp_path: Path) -> Path:
    root = tmp_path / "checkout"
    (root / "src").mkdir(parents=True)
    (root / "src/module.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "README.md").write_text("start\n", encoding="utf-8")
    (root / ".gitignore").write_text("ignored/\n*.log\n", encoding="utf-8")
    _git(root, "init", "--quiet", "--initial-branch=main")
    _git(root, "add", "--all")
    _git(root, "commit", "--quiet", "-m", "Starting checkpoint")
    return root


def test_changed_paths_and_baseline_text_follow_the_merge_base(tmp_path: Path) -> None:
    """Committed, staged and unstaged edits on a branch count; main moving on later does not."""
    root = _repository(tmp_path)
    baseline = _git(root, "rev-parse", "HEAD")
    assert repository.is_student_checkout(root)
    assert repository.baseline_commit(root) == baseline
    assert repository.changed_paths(root) == []

    _git(root, "checkout", "--quiet", "-b", "work")
    (root / "src/module.py").write_text("VALUE = 2\n", encoding="utf-8")
    _git(root, "commit", "--quiet", "-am", "Edit")
    (root / "new.txt").write_text("new\n", encoding="utf-8")
    _git(root, "add", "new.txt")
    (root / "README.md").write_text("edited\n", encoding="utf-8")

    assert sorted(repository.changed_paths(root)) == ["README.md", "new.txt", "src/module.py"]
    assert repository.baseline_text(root, "src/module.py") == "VALUE = 1\n"
    assert repository.baseline_text(root, "new.txt") is None, "absent at the starting checkpoint"
    (root / "untracked.txt").write_text("not added\n", encoding="utf-8")
    assert "untracked.txt" not in repository.changed_paths(root), "an untracked file is no change"

    _git(root, "checkout", "--quiet", "main")
    (root / "README.md").write_text("main moved on\n", encoding="utf-8")
    _git(root, "commit", "--quiet", "-am", "Main moves")
    _git(root, "checkout", "--quiet", "work")
    assert repository.baseline_commit(root) == baseline, "the merge base, not main's tip"


def test_baseline_text_decodes_utf_8_whatever_the_platform_encoding(tmp_path: Path) -> None:
    """A non-ASCII character at the starting checkpoint reads back as written, never mojibake."""
    root = tmp_path / "checkout"
    root.mkdir()
    (root / "module.py").write_text('"""Worker \u2014 a dash."""\n', encoding="utf-8")
    _git(root, "init", "--quiet", "--initial-branch=main")
    _git(root, "add", "--all")
    _git(root, "commit", "--quiet", "-m", "Starting checkpoint")
    _git(root, "checkout", "--quiet", "-b", "work")

    assert repository.baseline_text(root, "module.py") == '"""Worker \u2014 a dash."""\n'


def test_export_baseline_writes_the_starting_checkpoint_whole(tmp_path: Path) -> None:
    """The export holds the baseline's files with their baseline content; the commit is returned."""
    root = _repository(tmp_path)
    baseline = _git(root, "rev-parse", "HEAD")
    (root / "src/module.py").write_text("VALUE = 2\n", encoding="utf-8")

    commit = repository.export_baseline(root, tmp_path / "export")

    assert commit == baseline
    assert (tmp_path / "export/src/module.py").read_text(encoding="utf-8") == "VALUE = 1\n"
    assert (tmp_path / "export/README.md").is_file()
    assert not (tmp_path / "export/.git").exists()


def test_listed_files_follow_the_ignore_rules_and_include_untracked_files(tmp_path: Path) -> None:
    """Tracked and untracked-not-ignored files are listed; ignored ones are not."""
    root = _repository(tmp_path)
    (root / "seed.txt").write_text("untracked\n", encoding="utf-8")
    (root / "ignored").mkdir()
    (root / "ignored/cache.bin").write_bytes(b"\x00")
    (root / "run.log").write_text("log\n", encoding="utf-8")

    listed = repository.listed_files(root)

    assert listed is not None
    assert set(listed) == {".gitignore", "README.md", "src/module.py", "seed.txt"}


def test_a_nested_or_absent_repository_answers_nothing(tmp_path: Path) -> None:
    """A directory inside a repository, or outside any, has no student history."""
    root = _repository(tmp_path)
    nested = root / "src"
    assert not repository.is_student_checkout(nested)
    assert repository.changed_paths(nested) == []
    assert repository.baseline_text(nested, "module.py") is None
    with pytest.raises(repository.RepositoryError, match="no student history"):
        repository.export_baseline(nested, tmp_path / "nested-export")

    plain = tmp_path / "plain"
    plain.mkdir()
    assert repository.repository_root(plain) is None or not repository.is_student_checkout(plain)
    assert repository.changed_paths(plain) == []
