"""Coldline.

===================

File:              tests/security/security_scan.py
Component:         Security tooling — `poe security-scan`
Purpose:           Run the three pinned scanners over the working tree (or the starting checkpoint,
                    or a copy with a seed applied), print every finding with its stable id, mark
                    the ones at or above the thresholds, write the two reports, and exit per the
                    gate.
Interacts With:    tests/security/scanners.py, tests/security/gate.py, security/gate.yaml,
                    .github/workflows/security.yml, pyproject.toml (`poe security-scan`)
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          One command for the terminal and the hosted gate, every finding printed, a
                    verdict as an exit code
Tools:             Python 3.12, Docker

Exit 0 when no unsuppressed finding is at or above a threshold, 1 when one is (what the
``security-gate`` job fails on), 2 when a scanner could not run (Docker absent, an image
or the pinned database unavailable, a configuration error in ``security/gate.yaml``). By
default the working tree is scanned with the student's ``.gitleaks.toml`` and
``reports/security/scan.sarif`` and ``reports/security/sbom.cdx.json`` are written;
``--inventory`` applies the supplied configuration instead (every secret finding, whether
or not an allowlist entry covers it) and writes no report; ``--baseline`` scans the starting
checkpoint; ``--seed secret|vulnerable`` scans a temporary copy with that seed applied, as
``poe verify`` does, and leaves the checkout alone; ``--json`` prints the findings as JSON;
``--revision <sha>`` records the scanned commit in the SARIF report (the hosted job passes
the pull-request head it checked out).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from tests.security import gate, scanners, seeds

TASK_ROOT = Path(__file__).resolve().parents[2]


def build_parser() -> argparse.ArgumentParser:
    """Return the command's parser: the one place its switches are declared.

    The protected grading boundary (``fetch_pr_submission.py``) and the AI Student tooling
    build an invocation of this command for the starting checkpoint; their tests parse the
    exact argument vector they build with this parser, so a switch they pass exists here.
    """
    parser = argparse.ArgumentParser(
        description="Run the pinned scanners and judge the findings against security/gate.yaml."
    )
    parser.add_argument("--root", type=Path, default=TASK_ROOT)
    target = parser.add_mutually_exclusive_group()
    target.add_argument(
        "--inventory",
        action="store_true",
        help="apply the supplied Gitleaks configuration (no allowlist) and write no report",
    )
    target.add_argument(
        "--baseline", action="store_true", help="scan the starting checkpoint instead"
    )
    target.add_argument(
        "--seed",
        choices=seeds.KINDS,
        help="scan a temporary copy of the working tree with this seed applied",
    )
    parser.add_argument("--no-reports", action="store_true", help="do not write reports/security/")
    parser.add_argument("--json", action="store_true", help="print the findings as JSON")
    parser.add_argument(
        "--revision",
        help=(
            "the commit whose files are scanned, recorded in the SARIF report (the hosted job "
            "passes the checked-out pull-request head)"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Scan, print, write the reports when asked, and exit per the gate."""
    arguments = build_parser().parse_args(argv)
    root = arguments.root.resolve()
    try:
        thresholds = gate.load_thresholds(root=root)
    except gate.GateError as exc:
        print(f"security-scan: {exc}", file=sys.stderr)
        return 2
    writes_reports = not (arguments.no_reports or arguments.inventory or arguments.baseline)
    writes_reports = writes_reports and arguments.seed is None
    try:
        if arguments.baseline:
            report = scanners.scan_baseline(root, thresholds)
        elif arguments.seed is not None:
            report = scanners.scan_seeded(arguments.seed, root, thresholds)
        else:
            report = scanners.scan_working_tree(
                root, thresholds, inventory=arguments.inventory, sbom=writes_reports
            )
        written: tuple[Path, Path] | None = None
        if writes_reports:
            written = scanners.write_reports(
                report, root / scanners.REPORTS_DIRECTORY, revision=arguments.revision
            )
    except scanners.ScanError as exc:
        print(f"security-scan: {exc}", file=sys.stderr)
        return 2
    if arguments.json:
        print(json.dumps(report.as_document(), indent=2, sort_keys=True))
    else:
        for line in report.lines():
            print(line)
        if written is not None:
            first, second = written
            print(
                f"reports: {first.relative_to(root).as_posix()}, "
                f"{second.relative_to(root).as_posix()}"
            )
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
