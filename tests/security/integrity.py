"""Coldline.

===================

File:              tests/security/integrity.py
Component:         Security tooling — Verification integrity snapshot
Purpose:           Prove that the files `poe verify` judged are the files it finished with.
Interacts With:    pyproject.toml (`poe verify`), submission.yaml, infra/tofu/,
                    infra/opentofu.yaml, docs/governance/, docs/security/, docs/student/, src/,
                    security/, compose.yaml, .gitleaks.toml, .semgrepignore, tests/contract/,
                    tests/security/, tests/student/, tests/fixtures/, schemas/,
                    config/auth.yaml, infra/corpus/, uv.lock, the task and security workflows
Sprint/Task:       Sprint 4 — Project 4 / Task 4.10
Concepts:          Trusted bookends around a run, content hashes, tamper evidence
Tools:             Python 3.12, hashlib, json

``poe verify`` checks the answer sheet and the permitted-files boundary, then runs the stack,
OpenTofu and the scan over the declarations, and the checks on the inherited controls, in the
middle of a sequence of trusted steps. A file edited after a check read it would make the
run's verdicts describe a tree that no longer exists. This module is the first and the last
step of ``poe verify``:

- ``record`` (``poe integrity-record``) hashes the answer sheet, the student files and every
  trusted file the checks rely on (``TRUSTED_PATHS``) and writes the SHA-256 digests to a file
  **outside the repository**, in the system temporary directory, named after this checkout's
  path;
- ``check`` (``poe integrity-check``) recomputes them and fails, naming each file, if any was
  changed, added, or removed while verification ran. The snapshot is deleted after the
  check, so a later ``check`` without its ``record`` reports that, not a stale comparison.

``infra/tofu/`` is covered file by file, not as a directory: the declarations, the ignore file,
the provider configuration, the variables and the lock file. What OpenTofu writes there (its
``.terraform/`` directory and your sandbox's state) is not covered, and neither is ``poe
verify``'s own OpenTofu working copy under ``.tools/``, the evidence file ``poe attack-dev``
writes under ``evidence/``, the reports under ``reports/security/`` or the scanner cache:
they are written by runs, not supplied. This detects tampering during the run; it is not a
sandbox. Grading uses the committed tree, which no code in a checkout can rewrite, and the
hosted job runs ``poe verify`` whole, so an edit there turns the job red at this last step.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

TASK_ROOT = Path(__file__).resolve().parents[2]
# What the snapshot covers: the answer sheet and the other student files first, then the
# trusted material the checks rely on. A trailing slash names a directory, hashed file by file.
TRUSTED_PATHS: tuple[str, ...] = (
    "submission.yaml",
    "infra/tofu/main.tf",
    "infra/tofu/.trivyignore",
    "docs/student/iac-record.md",
    # The supplied OpenTofu project and the image it runs in.
    "infra/tofu/providers.tf",
    "infra/tofu/variables.tf",
    "infra/tofu/.terraform.lock.hcl",
    "infra/opentofu.yaml",
    # The stack's resource names the comparison reads.
    "compose.yaml",
    # The supplied governance material, the carried Task 4.6 completion among it.
    "docs/governance/",
    "docs/security/",
    # The settled threat model, the carried Task 4.6 corrections and this Task's contract.
    "docs/student/",
    # Every application module: the startup code and the carried completions among them.
    "src/",
    "security/",
    ".gitleaks.toml",
    ".semgrepignore",
    ".github/workflows/task.yml",
    ".github/workflows/security.yml",
    "tests/contract/",
    "tests/security/",
    "tests/student/",
    "tests/fixtures/",
    "schemas/",
    "docs/contracts/submission.schema.json",
    "config/auth.yaml",
    "infra/corpus/documents.jsonl",
    "pyproject.toml",
    "uv.lock",
)
SNAPSHOT_VARIABLE = "COLDLINE_INTEGRITY_SNAPSHOT"
IGNORED_DIRECTORIES = frozenset({"__pycache__"})
IGNORED_SUFFIXES = frozenset({".pyc"})


class IntegrityError(RuntimeError):
    """Report that the snapshot could not be recorded, found, or read, as opposed to a finding."""


def snapshot_path(root: Path = TASK_ROOT) -> Path:
    """Return where the snapshot for ``root`` lives: outside the repository, per checkout.

    ``COLDLINE_INTEGRITY_SNAPSHOT`` overrides it, for tests; otherwise the file sits in the
    system temporary directory under a name derived from the checkout's resolved path, so
    two checkouts never read each other's snapshot.
    """
    override = os.environ.get(SNAPSHOT_VARIABLE)
    if override:
        return Path(override)
    tag = hashlib.sha256(str(root.resolve()).encode("utf-8")).hexdigest()[:16]
    return Path(tempfile.gettempdir()) / f"coldline-verify-{tag}.json"


def trusted_files(root: Path = TASK_ROOT) -> list[Path]:
    """Return every file the snapshot covers, relative to ``root``, in a stable order.

    A file named both on its own and through a directory entry is listed once, at its first
    position.
    """
    files: list[Path] = []
    seen: set[Path] = set()

    def add(relative: Path) -> None:
        if relative not in seen:
            seen.add(relative)
            files.append(relative)

    for entry in TRUSTED_PATHS:
        path = root / entry
        if entry.endswith("/"):
            if not path.is_dir():
                continue
            for candidate in sorted(path.rglob("*")):
                relative = candidate.relative_to(root)
                if not candidate.is_file():
                    continue
                ignored_directory = bool(IGNORED_DIRECTORIES & set(relative.parts))
                if ignored_directory or candidate.suffix in IGNORED_SUFFIXES:
                    continue
                add(relative)
        elif path.is_file():
            add(Path(entry))
    return files


def snapshot(root: Path = TASK_ROOT) -> dict[str, str]:
    """Return the SHA-256 digest of every trusted file, keyed by its posix path."""
    return {
        relative.as_posix(): hashlib.sha256((root / relative).read_bytes()).hexdigest()
        for relative in trusted_files(root)
    }


def record(root: Path = TASK_ROOT, path: Path | None = None) -> Path:
    """Write the snapshot for ``root`` and return where it went."""
    target = snapshot_path(root) if path is None else path
    document = {
        "root": str(root.resolve()),
        "recorded_at": datetime.now(UTC).isoformat(),
        "files": snapshot(root),
    }
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(document, indent=2, sort_keys=True), encoding="utf-8")
    except OSError as exc:
        raise IntegrityError(
            f"the integrity snapshot could not be written to {target}: {exc}"
        ) from exc
    return target


def load(root: Path = TASK_ROOT, path: Path | None = None) -> dict[str, str]:
    """Return the recorded digests for ``root``, or raise saying why there are none."""
    target = snapshot_path(root) if path is None else path
    if not target.is_file():
        raise IntegrityError(
            f"no integrity snapshot at {target}: `poe integrity-record` runs first in "
            "`poe verify`, and `poe integrity-check` compares against it"
        )
    try:
        document = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise IntegrityError(
            f"the integrity snapshot at {target} could not be read: {exc}"
        ) from exc
    files = document.get("files") if isinstance(document, dict) else None
    recorded_root = document.get("root") if isinstance(document, dict) else None
    if not isinstance(files, dict) or not all(
        isinstance(name, str) and isinstance(digest, str) for name, digest in files.items()
    ):
        raise IntegrityError(f"the integrity snapshot at {target} has no file digests")
    if recorded_root != str(root.resolve()):
        raise IntegrityError(
            f"the integrity snapshot at {target} was recorded for {recorded_root!r}, "
            f"not for {str(root.resolve())!r}"
        )
    return dict(files)


def compare(before: dict[str, str], after: dict[str, str]) -> list[str]:
    """Return one finding per file whose digest, presence, or absence changed."""
    findings: list[str] = []
    for name in sorted(set(before) | set(after)):
        if name not in after:
            findings.append(f"{name} was removed during verification")
        elif name not in before:
            findings.append(f"{name} was added during verification")
        elif before[name] != after[name]:
            findings.append(f"{name} changed during verification")
    return findings


def check(root: Path = TASK_ROOT, path: Path | None = None) -> list[str]:
    """Compare the trusted files with the recorded snapshot, then delete the snapshot."""
    target = snapshot_path(root) if path is None else path
    before = load(root, target)
    findings = compare(before, snapshot(root))
    try:
        target.unlink()
    except OSError:
        pass
    return findings


def main(argv: list[str] | None = None) -> int:
    """Record the snapshot, or check the tree against it and print what changed."""
    parser = argparse.ArgumentParser(
        description="Record or check the integrity snapshot `poe verify` brackets its run with."
    )
    parser.add_argument("action", choices=("record", "check"))
    parser.add_argument("--root", type=Path, default=TASK_ROOT)
    arguments = parser.parse_args(argv)
    try:
        if arguments.action == "record":
            target = record(arguments.root)
            count = len(trusted_files(arguments.root))
            print(f"integrity: recorded {count} trusted files to {target}")
            return 0
        found = check(arguments.root)
    except IntegrityError as exc:
        print(f"integrity: {exc}", file=sys.stderr)
        return 2
    if found:
        print(
            "integrity: files changed while `poe verify` ran; the run's verdicts do not "
            "describe the tree it finished with:",
            file=sys.stderr,
        )
        for finding in found:
            print(f"- {finding}", file=sys.stderr)
        return 1
    print("integrity: every trusted file is as it was when `poe verify` began.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
