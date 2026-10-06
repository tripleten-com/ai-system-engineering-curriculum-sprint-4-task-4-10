"""Coldline.

===================

File:              tests/unit/security/test_value_findings.py
Component:         Unit tests — No value in any assertion
Purpose:           Prove the one comparison the assessed rows make against a stored value names the
                    version and the output only, and that a failing row rendered by pytest, on the
                    terminal and in the junit report, carries no value, on the rows' path, on the
                    initializer test's path and on the generated-key format check's path.
Interacts With:    tests/security/secret_tools.py, tests/contract/test_security_contract.py,
                    tests/unit/api/test_initialize_secret.py,
                    tests/unit/security/test_secret_tools.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          Fingerprints instead of values, assertion rewriting kept away from secrets
Tools:             Python 3.12, pytest (as a subprocess), junit XML

The sentinel the probe looks for is handed to the subprocess through a file named in the
environment, so neither this module nor the probe module spells it: what the failing run
prints is judged, not what its source holds.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from adapters.secrets import SecretVersion
from tests.security import secret_tools

TASK_ROOT = Path(__file__).resolve().parents[3]
SENTINEL_VARIABLE = "COLDLINE_VALUE_PROBE_FILE"
PROBE = '''"""A probe: the assessed rows' comparison, failing on purpose."""

import os
from pathlib import Path

from adapters.secrets import SecretVersion
from tests.security import secret_tools


def test_a_version_value_in_an_output_is_named_by_version_only():
    value = Path(os.environ["COLDLINE_VALUE_PROBE_FILE"]).read_text(encoding="utf-8").strip()
    versions = [(SecretVersion("probe-version-1", "0123456789ab", ("AWSCURRENT",)), value)]
    outputs = {"the probe output": "prefix " + value + " suffix"}
    findings = secret_tools.value_findings(outputs, versions)
    assert findings == [], "; ".join(findings)
'''
# The initializer test's path (tests/unit/api/test_initialize_secret.py): the provisioned
# first value is compared with the supplied one before the assertion, so a regression in the
# provisioning fails on a boolean and renders neither operand.
INITIALIZER_PROBE = '''"""A probe: the initializer test's comparison, failing on purpose."""

import os
from pathlib import Path


def test_the_initializer_provisioned_the_supplied_first_version():
    sentinel_file = Path(os.environ["COLDLINE_VALUE_PROBE_FILE"])
    expected = sentinel_file.read_text(encoding="utf-8").strip()
    call = {"name": "coldline/worker/model-provider-key", "first_value": expected + "-drifted"}
    matches_initial = call["first_value"] == expected
    assert matches_initial, "the initializer must provision the supplied first version"
'''
# The generated-key format check's path (tests/unit/security/test_secret_tools.py): a
# generated value is matched against the supplied rule before the assertion, so a value
# outside the format fails on a boolean and renders neither the value nor the pattern.
FORMAT_PROBE = '''"""A probe: the generated-key format check, failing on purpose."""

import os
from pathlib import Path

from tests.security import seeds


def test_a_generated_value_is_in_the_supplied_provider_key_format():
    value = Path(os.environ["COLDLINE_VALUE_PROBE_FILE"]).read_text(encoding="utf-8").strip()
    matches_rule = seeds.matches_supplied_rule(value)
    assert matches_rule, "a generated value matches the supplied provider-key rule"
'''


def _versions(*values: str) -> list[tuple[SecretVersion, str]]:
    return [
        (SecretVersion(f"version-{index}", f"{index:012d}", ("AWSCURRENT",)), value)
        for index, value in enumerate(values, start=1)
    ]


def test_findings_name_the_version_and_the_output_and_never_the_value() -> None:
    """One finding per (version, output) that holds the value; the text names ids only."""
    versions = _versions("unit-value-alpha", "unit-value-beta", "")
    outputs = {
        "poe secret-status": "current version version-1 (fingerprint 000000000001)",
        "worker log": "authenticated with unit-value-alpha and later unit-value-beta",
        "stored record": "nothing of note",
    }

    findings = secret_tools.value_findings(outputs, versions)

    assert findings == [
        "version version-1 (fingerprint 000000000001)'s value appears in worker log",
        "version version-2 (fingerprint 000000000002)'s value appears in worker log",
    ]
    assert all("unit-value" not in finding for finding in findings)
    assert secret_tools.value_findings(outputs, _versions("absent")) == []
    assert secret_tools.value_findings({}, versions) == []


@pytest.mark.parametrize(
    "source, marker",
    [
        (PROBE, "probe-version-1"),
        (INITIALIZER_PROBE, "must provision the supplied first version"),
        (FORMAT_PROBE, "matches the supplied provider-key rule"),
    ],
    ids=["value-findings", "initializer", "generated-format"],
)
def test_a_failing_row_renders_no_value_on_the_terminal_or_in_the_junit_report(
    tmp_path: Path, source: str, marker: str
) -> None:
    """A probe that fails a comparison with a sentinel value prints its marker, not the value.

    Three probes: the assessed rows' `value_findings` comparison, the initializer test's
    first-value comparison and the secret tools' generated-key format check (the sentinel
    is outside the format). Each is written beside a file holding the sentinel and run
    under pytest with a junit report, rooted and cut at the temporary directory (so pytest
    collects nothing beside the probe) with the Task's configuration and the Task root on
    the path (so the Task's packages import as the assessed module's do), and must fail; then its
    stdout, stderr and junit report are searched for the sentinel, which must appear in
    none of them, while the marker (the version id, or the assertion's message) does.
    """
    sentinel = "sentinel-value-" + "7f3a9c2e1b5d" * 2
    sentinel_file = tmp_path / "sentinel.txt"
    sentinel_file.write_text(sentinel + "\n", encoding="utf-8")
    probe = tmp_path / "test_value_probe.py"
    probe.write_text(source, encoding="utf-8")
    report = tmp_path / "probe.xml"
    search_path = os.pathsep.join([str(TASK_ROOT), os.environ.get("PYTHONPATH", "")])
    environment = {**os.environ, SENTINEL_VARIABLE: str(sentinel_file), "PYTHONPATH": search_path}

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            str(probe),
            "-p",
            "no:cacheprovider",
            "--rootdir",
            str(tmp_path),
            # Without this, pytest walks every ancestor of the probe that is not an ancestor
            # of the Task root (the system temporary directory included) and compares each
            # entry it finds there with the probe's path, which is slow and fails when
            # another process removes an entry meanwhile. The cut keeps the walk inside
            # the temporary directory.
            "--confcutdir",
            str(tmp_path),
            "-c",
            str(TASK_ROOT / "pyproject.toml"),
            f"--junitxml={report}",
        ],
        cwd=TASK_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
        check=False,
    )

    # The outcomes are computed first: a failing assertion here must not print the
    # captured output either, which would carry the sentinel if the probe had leaked it.
    failed = completed.returncode == 1
    assert failed, f"the probe must fail (exit {completed.returncode})"
    assert marker in completed.stdout, "the failing row names its marker"
    assert report.is_file(), "pytest wrote the junit report"
    junit = report.read_text(encoding="utf-8")
    leaked = sentinel in completed.stdout or sentinel in completed.stderr or sentinel in junit
    assert not leaked, "the sentinel reached the terminal or the junit report"
    assert marker in junit
