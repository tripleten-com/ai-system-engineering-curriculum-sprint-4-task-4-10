"""Coldline.

===================

File:              tests/security/repository.py
Component:         Security tooling — The checkout's Git history
Purpose:           Answer the three questions the Task 4.5 checks ask Git: which paths changed since
                    the starting checkpoint, what a file held there, and what the whole starting
                    checkpoint held.
Interacts With:    tests/contract/submission_validation.py, tests/security/fix_binding.py,
                    tests/security/scanners.py, tests/contract/test_authoring_contract.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          The merge base as the starting checkpoint, a student history versus the
                    authoring snapshot
Tools:             Python 3.12, Git

A student's work happens ahead of ``main``: on a branch, or as uncommitted edits, while
``main`` itself keeps moving as the repository receives updates after the fork. The
starting checkpoint is therefore the commit the student actually started from, the merge
base of ``HEAD`` with ``main`` (``origin/main`` first), not the repository's first commit.
Every helper here takes the Task root and answers for that checkpoint. When the Task root
is nested inside another repository (the curriculum's authoring snapshot), there is no
student history to read, and the helpers say so (``None``, or an empty list) instead of
reading the enclosing repository's.
"""

from __future__ import annotations

import subprocess
import tempfile
import zipfile
from pathlib import Path

TASK_ROOT = Path(__file__).resolve().parents[2]
GIT_TIMEOUT_SECONDS = 300
BASELINE_CANDIDATES = ("origin/main", "main")


class RepositoryError(RuntimeError):
    """Report that Git could not answer, as opposed to an answer about the checkout."""


def _git(root: Path, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run one Git command in ``root``."""
    try:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RepositoryError(f"git {arguments[0]} could not run in {root}: {exc}") from exc
    if check and completed.returncode != 0:
        raise RepositoryError(
            f"git {arguments[0]} failed in {root} (exit {completed.returncode}): "
            f"{completed.stderr.strip()}"
        )
    return completed


def repository_root(root: Path) -> Path | None:
    """Return the root of the repository ``root`` is in, or None when it is in none."""
    completed = _git(root, "rev-parse", "--show-toplevel", check=False)
    if completed.returncode != 0:
        return None
    return Path(completed.stdout.strip()).resolve()


def is_student_checkout(root: Path) -> bool:
    """Return whether ``root`` is itself a repository root (a student's or a generated checkout).

    The authoring snapshot is nested inside the curriculum repository; only a generated
    repository's own history defines student changes.
    """
    top = repository_root(root)
    return top is not None and top == root.resolve()


def baseline_commit(root: Path) -> str:
    """Return the commit a checkout's changes are measured against: the merge base with main.

    With no ``main`` reachable, the repository's single root commit.
    """
    for candidate in BASELINE_CANDIDATES:
        probe = _git(root, "rev-parse", "--verify", "--quiet", candidate, check=False)
        if probe.returncode == 0:
            return _git(root, "merge-base", "HEAD", candidate).stdout.strip()
    roots = _git(root, "rev-list", "--max-parents=0", "HEAD").stdout.split()
    if len(roots) != 1:
        raise RepositoryError("the repository must have exactly one protected root commit")
    return roots[0]


def changed_paths(root: Path = TASK_ROOT) -> list[str]:
    """Return the paths that differ from the starting checkpoint, committed or not.

    Empty when ``root`` is nested inside another repository: the authoring snapshot has no
    student history. Raises ``RepositoryError`` when Git itself cannot answer.
    """
    if not is_student_checkout(root):
        return []
    baseline = baseline_commit(root)
    diff = _git(root, "diff", "--name-only", baseline).stdout
    return [line for line in diff.splitlines() if line]


def baseline_text(root: Path, path: str) -> str | None:
    """Return what ``path`` held at the starting checkpoint, or None when it did not exist there.

    None as well when ``root`` has no student history.
    """
    if not is_student_checkout(root):
        return None
    baseline = baseline_commit(root)
    completed = _git(root, "show", f"{baseline}:{path}", check=False)
    if completed.returncode != 0:
        return None
    return completed.stdout


def export_baseline(root: Path, destination: Path) -> str:
    """Write the whole starting checkpoint under ``destination`` and return its commit."""
    if not is_student_checkout(root):
        raise RepositoryError(
            f"{root} has no student history: it is nested inside another repository, or is "
            "no repository at all"
        )
    baseline = baseline_commit(root)
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="coldline-baseline-") as temporary:
        archive = Path(temporary) / "baseline.zip"
        _git(root, "archive", "--format=zip", f"--output={archive}", baseline)
        with zipfile.ZipFile(archive) as bundle:
            bundle.extractall(destination)
    return baseline


def listed_files(root: Path) -> list[str] | None:
    """Return the files Git tracks or would track under ``root``, or None outside a repository.

    Tracked files, plus untracked files that no ignore rule covers: the files at the
    head of a pull request, as the gate sees them, with a seed file that is not committed
    yet included and the virtual environment, the tool cache and the generated reports
    left out. Paths are relative to ``root`` with forward slashes.
    """
    if repository_root(root) is None:
        return None
    listing = _git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard").stdout
    return [entry for entry in listing.split("\0") if entry]
