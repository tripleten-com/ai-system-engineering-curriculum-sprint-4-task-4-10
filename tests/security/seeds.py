"""Coldline.

===================

File:              tests/security/seeds.py
Component:         Security tooling — The two supplied seeds
Purpose:           Write the supplied fake provider key and the supplied vulnerable dependency pin
                    into their scan locations, for the Step 4 demonstration branches and for the
                    temporary copies `poe verify` scans.
Interacts With:    .gitleaks.toml (the supplied provider-key rule), security/scanners.yaml,
                    tests/security/scanners.py, tests/contract/test_security_contract.py,
                    pyproject.toml (`poe seed-secret`, `poe seed-vulnerable`)
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          A gate proven on a known-bad change, seeds outside every permitted and
                    suppressible path
Tools:             Python 3.12

Two seeds, each written to a supplied path under ``security/seed/``, outside the permitted
files and outside any path a suppression may name:

- ``poe seed-secret`` writes ``security/seed/provider-key.txt`` holding a fake key in the
  Coldline provider-key format (``cpk_`` and 32 letters and digits), which the supplied
  rule in ``.gitleaks.toml`` matches and which is no vendor's format, so no hosting
  platform's push protection intercepts the demonstration push. The key is spelled in two
  halves below so this file never holds it in the format the rule matches;
- ``poe seed-vulnerable`` writes ``security/seed/requirements.txt`` pinning a release of a
  widely used package with a published high-severity vulnerability, which Trivy reads
  beside ``uv.lock``.

Both commands overwrite an existing seed file and print the path and what to do next.
``apply`` writes the same file into any tree, which is how ``poe verify`` seeds a
temporary copy of the working tree and leaves the checkout alone.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

TASK_ROOT = Path(__file__).resolve().parents[2]
SEED_DIRECTORY = Path("security/seed")
SECRET_SEED_PATH = SEED_DIRECTORY / "provider-key.txt"
VULNERABLE_SEED_PATH = SEED_DIRECTORY / "requirements.txt"
KINDS: tuple[str, ...] = ("secret", "vulnerable")
SUPPLIED_RULE_ID = "coldline-provider-key"
SUPPLIED_RULE_REGEX = r"\bcpk_[A-Za-z0-9]{32}\b"
KEY_PREFIX = "cpk_"
# The fake key's body is derived, not written: no key-shaped literal sits in this file, so
# it matches no scanner rule until a seed command writes the joined key into the seed file.
_FAKE_KEY_BODY = hashlib.sha256(b"coldline task 4.5 seeded secret").hexdigest()[:32]
FAKE_KEY = KEY_PREFIX + _FAKE_KEY_BODY
VULNERABLE_PIN = "pyyaml==5.3"
SEED_PATHS: dict[str, Path] = {"secret": SECRET_SEED_PATH, "vulnerable": VULNERABLE_SEED_PATH}


def secret_seed_text() -> str:
    """Return the content of the fake-key seed file."""
    return (
        "# Coldline - Task 4.5\n"
        "# Supplied seed for the Step 4 demonstration branch: a fake model-provider key in the\n"
        "# Coldline provider-key format. It is a credential of nothing and grants nothing; it\n"
        "# exists so the security gate can be shown refusing a committed key. Commit it on a\n"
        "# draft branch, watch the gate fail, revert, and never merge the branch.\n"
        f"model_provider_key = {FAKE_KEY}\n"
    )


def vulnerable_seed_text() -> str:
    """Return the content of the vulnerable-dependency seed file."""
    return (
        "# Coldline - Task 4.5\n"
        "# Supplied seed for the Step 4 demonstration branch: a pinned release with a published\n"
        "# high-severity vulnerability, read by Trivy beside uv.lock. Nothing installs it. Commit\n"
        "# it on a draft branch, watch the gate fail, revert, and never merge the branch.\n"
        f"{VULNERABLE_PIN}\n"
    )


def seed_text(kind: str) -> str:
    """Return the seed file's content for one kind."""
    if kind == "secret":
        return secret_seed_text()
    if kind == "vulnerable":
        return vulnerable_seed_text()
    raise ValueError(f"unknown seed {kind!r}; choose one of {', '.join(KINDS)}")


def apply(kind: str, root: Path = TASK_ROOT) -> Path:
    """Write one seed into ``root`` and return the file written."""
    target = root / SEED_PATHS[kind] if kind in SEED_PATHS else None
    if target is None:
        raise ValueError(f"unknown seed {kind!r}; choose one of {', '.join(KINDS)}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(seed_text(kind), encoding="utf-8")
    return target


def matches_supplied_rule(text: str) -> bool:
    """Return whether ``text`` holds a key in the supplied provider-key format."""
    return re.search(SUPPLIED_RULE_REGEX, text) is not None


def main(argv: list[str] | None = None) -> int:
    """Write the named seed into the working tree."""
    parser = argparse.ArgumentParser(
        description="Write one supplied seed for a demonstration branch."
    )
    parser.add_argument("kind", choices=KINDS)
    parser.add_argument("--root", type=Path, default=TASK_ROOT)
    arguments = parser.parse_args(argv)
    written = apply(arguments.kind, arguments.root)
    relative = SEED_PATHS[arguments.kind].as_posix()
    print(f"seed-{arguments.kind}: wrote {relative}")
    if arguments.kind == "secret":
        print(
            "Commit it on a draft branch from your Step 3 commit, push, and read the "
            "security-gate run: Gitleaks reports the fake key under the supplied rule. Then "
            "revert the commit, push again, and close the pull request without merging."
        )
    else:
        print(
            "Commit it on a draft branch from your Step 3 commit, push, and read the "
            "security-gate run: Trivy reports the pinned release's published vulnerability. "
            "Then revert the commit, push again, and close the pull request without merging."
        )
    print(f"(file: {written})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
