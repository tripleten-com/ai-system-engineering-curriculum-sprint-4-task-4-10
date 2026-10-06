"""Coldline.

===================

File:              tests/security/security_setup.py
Component:         Security tooling — `poe security-setup`
Purpose:           Pull the three pinned scanner images and download the pinned vulnerability
                    database once, so every later scan runs offline.
Interacts With:    tests/security/scanners.py, security/scanners.yaml,
                    .github/workflows/security.yml, pyproject.toml (`poe security-setup`)
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          Pinned tools fetched once, scans that never fetch
Tools:             Python 3.12, Docker

The one network step of the gate. Idempotent: an image already present and a database
already in its digest-named directory under ``.tools/trivy-cache/`` (with the marker that
names the pinned reference beside it) are left alone; a cache downloaded for another
digest is not reused. ``poe security-scan`` and the assessed checks download the database
themselves when it is missing, so this command is a convenience and a CI step, not a
precondition; ``--no-pull`` skips the images.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from tests.security import scanners

TASK_ROOT = Path(__file__).resolve().parents[2]


def main(argv: list[str] | None = None) -> int:
    """Pull the images and download the database; print what is in place."""
    parser = argparse.ArgumentParser(description="Prepare the pinned scanners for offline scans.")
    parser.add_argument("--root", type=Path, default=TASK_ROOT)
    parser.add_argument("--no-pull", action="store_true", help="skip pulling the scanner images")
    arguments = parser.parse_args(argv)
    root = arguments.root.resolve()
    try:
        pins = scanners.load_pins(root)
        if not arguments.no_pull:
            for reference in scanners.pull_images(root):
                print(f"security-setup: image present: {reference}")
        cache = scanners.ensure_trivy_database(root, pins=pins)
    except scanners.ScanError as exc:
        print(f"security-setup: {exc}", file=sys.stderr)
        return 2
    print(
        f"security-setup: Trivy database {pins.trivy_db.reference} is in "
        f"{cache.relative_to(root).as_posix()}; scans run offline from here."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
