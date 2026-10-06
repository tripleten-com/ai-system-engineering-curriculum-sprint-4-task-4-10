"""Coldline.

===================

File:              tests/security/attack_dev.py
Component:         Security tooling — The development attack scenario
Purpose:           Run the supplied development attack through the running stack and write the
                    stage evidence to evidence/attack-dev.json.
Interacts With:    tests/security/attack_scenario.py, tests/fixtures/attacks/development.json,
                    evidence/attack-dev.json, pyproject.toml (`poe attack-dev`)
Sprint/Task:       Sprint 4 — Project 4 / Task 4.6
Concepts:          Evidence from a real run, deterministic stage names, nothing personal in the file
Tools:             Python 3.12, httpx, Docker Compose

``poe attack-dev`` reads the supplied scenario (``tests/fixtures/attacks/development.json``:
one unauthorized token fixture, one refused answer, one handling note with marked personal
values), sends it through the running stack with the shared procedure, writes the four
stages to ``evidence/attack-dev.json`` (Git-ignored; overwritten on every run) and prints
the stage summary. The file holds what each stage sent, what the control did, the outcome
the decision policy reads, the exception id and the audit event ids; marked values appear
as labels, and no token, key or redacted text is written. It exits 0 whatever the outcomes
were (a stage that did not hold is evidence, not a tooling failure) and 2 when the run could
not be made, with the step that did not answer.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from tests.runtime_config import host_port
from tests.security.attack_scenario import (
    AttackResult,
    LiveInterfaces,
    ScenarioError,
    load_scenario_text,
    run_attack,
    summary_lines,
)

TASK_ROOT = Path(__file__).resolve().parents[2]
SCENARIO_PATH = Path("tests/fixtures/attacks/development.json")
EVIDENCE_PATH = Path("evidence/attack-dev.json")


def evidence_document(result: AttackResult, *, scenario_file: str) -> dict[str, Any]:
    """Return the evidence file's content for one run: the stages plus when and from what."""
    document = result.as_document()
    document["generated_at"] = datetime.now(UTC).isoformat()
    document["scenario_file"] = scenario_file
    return document


def write_evidence(document: dict[str, Any], path: Path) -> None:
    """Write the evidence document, creating the ignored directory when needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    """Run the development attack and write the evidence; print the stage summary."""
    parser = argparse.ArgumentParser(
        description="Send the supplied development attack through the running stack."
    )
    parser.add_argument("--root", type=Path, default=TASK_ROOT)
    parser.add_argument(
        "--scenario",
        type=Path,
        default=None,
        help=f"the scenario file (default: {SCENARIO_PATH.as_posix()} under the root)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help=f"where to write the evidence (default: {EVIDENCE_PATH.as_posix()} under the root)",
    )
    arguments = parser.parse_args(argv)
    root: Path = arguments.root
    scenario_path = root / SCENARIO_PATH if arguments.scenario is None else arguments.scenario
    output = root / EVIDENCE_PATH if arguments.output is None else arguments.output
    try:
        scenario = load_scenario_text(
            scenario_path.read_text(encoding="utf-8"), require_expected=False
        )
    except (OSError, ScenarioError) as exc:
        print(f"attack-dev: the scenario file could not be used: {exc}", file=sys.stderr)
        return 2
    port = host_port("COLDLINE_API_HOST_PORT", 8000, root=root)
    try:
        with httpx.Client(base_url=f"http://localhost:{port}", timeout=10.0) as client:
            result = run_attack(scenario, LiveInterfaces(client, root))
    except ScenarioError as exc:
        print(
            f"attack-dev: the run could not be made: {exc}; is the stack running "
            "(`poe start`, `poe ready`, `poe ingest`)?",
            file=sys.stderr,
        )
        return 2
    try:
        relative = scenario_path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        relative = scenario_path.name
    write_evidence(evidence_document(result, scenario_file=relative), output)
    print(f"attack-dev: scenario {result.scenario_id}, exception {result.exception_id}")
    for line in summary_lines(result):
        print(f"  {line}")
    try:
        shown = output.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        shown = str(output)
    print(f"attack-dev: wrote {shown}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
