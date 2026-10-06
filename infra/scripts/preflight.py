"""Coldline.

===================

File:              infra/scripts/preflight.py
Component:         Developer tooling — Preflight
Purpose:           Check the local toolchain without changing the environment.
Interacts With:    Local workstation, uv, and Docker Compose
Sprint/Task:       Sprint 1 — Project 1
Concepts:          Reproducibility, preflight checks, bootstrap
Tools:             Python 3.12
"""

import shutil
import subprocess
import sys
from pathlib import Path

TASK_ROOT = Path(__file__).resolve().parents[2]
UV_EXECUTABLE = TASK_ROOT / ".tools" / "bin" / ("uv.exe" if sys.platform == "win32" else "uv")


def main() -> int:
    """Return success only for the supported Python, uv, and Compose tools."""
    errors: list[str] = []
    if sys.version_info[:2] != (3, 12):
        errors.append("Python 3.12 is required")
    _require_version("uv", [str(UV_EXECUTABLE), "--version"], "uv 0.11.8", errors)
    _require_version("docker", ["docker", "compose", "version"], "Docker Compose version", errors)
    if errors:
        for error in errors:
            print(f"preflight failed: {error}", file=sys.stderr)
        return 1
    print("Preflight passed: Python 3.12, uv 0.11.8, and Docker Compose v2 are available.")
    return 0


def _require_version(command: str, args: list[str], expected: str, errors: list[str]) -> None:
    """Append an actionable error when a command or version is unavailable."""
    executable = args[0]
    if not Path(executable).is_file() and shutil.which(executable) is None:
        errors.append(f"{command} is unavailable at {executable}; run the bootstrap first")
        return
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    output = f"{result.stdout} {result.stderr}".strip()
    if result.returncode != 0 or expected not in output:
        errors.append(f"expected {expected}; observed {output or 'no version output'}")


if __name__ == "__main__":
    raise SystemExit(main())
