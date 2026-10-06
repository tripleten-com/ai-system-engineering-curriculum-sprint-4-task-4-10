"""Coldline.

===================

File:              tests/unit/test_migration_template.py
Component:         Migration generator regression tests
Purpose:           Verify generated revisions satisfy the supplied formatting gates.
Interacts With:    Alembic Mako template and Ruff
Sprint/Task:       Sprint 2 — Task 2.6
Concepts:          Reproducible code generation, cross-platform formatting
Tools:             Python 3.12, pytest, Mako, Ruff
"""

import subprocess
import sys
from pathlib import Path

import pytest
from mako.template import Template


@pytest.mark.parametrize("imports", ["", "from sqlalchemy.dialects import postgresql"])
def test_revision_template_generates_sorted_imports(imports: str) -> None:
    """Exercise both empty and populated Alembic autogeneration imports."""
    template = Path(__file__).resolve().parents[2] / "migrations/script.py.mako"
    rendered = Template(filename=str(template)).render(
        up_revision="fixture",
        down_revision="previous",
        message="Fixture revision",
        create_date="2026-09-08",
        branch_labels=None,
        depends_on=None,
        imports=imports,
        upgrades="pass",
        downgrades="pass",
        comma=lambda value: value,
    )
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "ruff",
            "check",
            "--select",
            "I",
            "--stdin-filename",
            "revision.py",
            "-",
        ],
        input=rendered.encode("utf-8"),
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, (result.stdout + result.stderr).decode("utf-8")
    formatted = subprocess.run(
        [sys.executable, "-m", "ruff", "format", "--check", "--stdin-filename", "revision.py", "-"],
        input=rendered.encode("utf-8"),
        capture_output=True,
        check=False,
    )
    assert formatted.returncode == 0, (formatted.stdout + formatted.stderr).decode("utf-8")
