"""Coldline.

===================

File:              tests/security/tofu_scan.py
Component:         Infrastructure tooling — `poe tofu-scan`
Purpose:           Run Trivy's configuration scan over the declarations in infra/tofu/ with
                    infra/tofu/.trivyignore as its ignore file, print each reported check id with
                    the resources it names, and judge a triage against the scan.
Interacts With:    security/scanners.yaml (the pinned Trivy image), infra/tofu/,
                    tests/security/tofu.py, tests/security/iac_run.py,
                    tests/contract/test_iac_contract.py, pyproject.toml
Sprint/Task:       Sprint 4 — Project 4 / Task 4.10
Concepts:          A scan of declarations before they are applied, a check id that names several
                    resources, an accepted finding that carries its reason
Tools:             Python 3.12, Docker, Trivy

**What is scanned.** A copy of the top-level files of ``infra/tofu/`` (the ``.tf`` files and
the lock file), never OpenTofu's ``.terraform/`` directory or state, and never LocalStack: the
scan reads the declarations, not the running resources. The ignore file is mounted beside the
copy and passed with ``--ignorefile``; a check id it lists is not reported.

**The pins.** The Trivy image is the one ``security/scanners.yaml`` pins by digest for the
security gate. The configuration checks are the bundle compiled into that image: every scan
runs with ``--skip-check-update``, with a fresh empty cache and with the network off, so Trivy
can neither download a newer bundle nor reuse one a different version left behind. The image
digest therefore pins the checks too, and re-pinning the image is the one way to change them.

**What is printed.** Every check id the scan reports as failing, its severity and title, each
resource it names (one check id can name several), and the setting it recommends. Trivy's
JSON names a check by ``ID`` and, in some versions, by an ``AVDID`` alias as well; both are
printed when they differ. ``AVD-AWS-0001`` and ``AWS-0001`` are one check id wherever one is
compared: in the answer sheet, in ``.trivyignore`` (the copy Trivy reads lists each entry in
both spellings) and in the scan's output alike. The scan reports and judges nothing else: exit 0
when it ran, whatever it found; 2 when it could not run.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tests.security import scanners, tofu

TASK_ROOT = Path(__file__).resolve().parents[2]
SCAN_MOUNT = "/scan"
IGNORE_MOUNT = "/ignore"
IGNORE_NAME = "trivyignore"
FAIL = "FAIL"
PASS = "PASS"
FIX = "fix"
ACCEPT = "accept"
AVD_PREFIX = "AVD-"
TRIVY_CONFIG_FLAGS: tuple[str, ...] = ("--skip-check-update", "--include-non-failures")


class ScanError(RuntimeError):
    """Report that the configuration scan could not run, as opposed to what it found."""


def normalize(check_id: str) -> str:
    """Return a check id in one comparable form: upper case, without an ``AVD-`` prefix.

    ``AVD-AWS-0001`` and ``AWS-0001`` are the same check: Trivy prints one or the other as a
    check's ``ID``, depending on its version, and keeps the ``AVD-`` form as ``AVDID``.
    """
    text = check_id.strip().upper()
    return text[len(AVD_PREFIX) :] if text.startswith(AVD_PREFIX) else text


def alternative_form(check_id: str) -> str:
    """Return the other spelling of a check id: with ``AVD-`` when it has none, else without."""
    text = check_id.strip()
    if text.upper().startswith(AVD_PREFIX):
        return text[len(AVD_PREFIX) :]
    return f"{AVD_PREFIX}{text}"


def trivy_ignore_text(ignore_text: str) -> str:
    """Return the ignore file Trivy reads: each entry in both spellings of its check id.

    Trivy matches an entry against the check's ``ID`` and, in some versions, its ``AVDID``;
    writing both spellings makes an entry hide its check whichever form the pinned image
    prints. Entries are counted and judged from your file as written, never from this copy.
    """
    lines: list[str] = []
    for raw in ignore_text.splitlines():
        lines.append(raw)
        line = raw.strip()
        if line and not line.startswith("#"):
            check_id, _, rest = line.partition(" ")
            lines.append(f"{alternative_form(check_id)} {rest}".rstrip())
    return "\n".join(lines) + ("\n" if lines else "")


@dataclass(frozen=True)
class CheckResult:
    """One check's result on one resource: its ids, status, severity and recommendation."""

    check_id: str
    alias: str
    status: str
    severity: str
    title: str
    resolution: str
    resource: str
    target: str
    line: int | None

    def names(self, check_id: str) -> bool:
        """Return whether ``check_id`` names this check, in either of its forms."""
        wanted = normalize(check_id)
        return wanted in {normalize(self.check_id), normalize(self.alias or self.check_id)}

    @property
    def where(self) -> str:
        """Return the resource, with the file and line when the scan gives them."""
        place = self.target if self.line is None else f"{self.target}:{self.line}"
        return f"{self.resource} ({place})" if place else self.resource


@dataclass(frozen=True)
class ScanResult:
    """Every check result of one scan."""

    results: tuple[CheckResult, ...]

    def reports(self, check_id: str, status: str = FAIL) -> list[CheckResult]:
        """Return the results with ``status`` for the check ``check_id`` names."""
        return [
            result for result in self.results if result.status == status and result.names(check_id)
        ]

    def failing(self) -> dict[str, list[CheckResult]]:
        """Return the failing results grouped by check id, in check id order."""
        grouped: dict[str, list[CheckResult]] = {}
        for result in self.results:
            if result.status == FAIL:
                grouped.setdefault(result.check_id, []).append(result)
        return dict(sorted(grouped.items()))

    def lines(self, ignore_label: str) -> list[str]:
        """Render the failing check ids, the resources each names and its recommendation."""
        failing = self.failing()
        lines = [f"tofu-scan: Trivy configuration scan of infra/tofu/ ({ignore_label})"]
        for check_id, results in failing.items():
            first = results[0]
            alias = f" (also {first.alias})" if first.alias and first.alias != check_id else ""
            lines.append(f"  {check_id}{alias}  {first.severity}  {first.title}")
            for result in results:
                lines.append(f"      resource: {result.where}")
            if first.resolution:
                lines.append(f"      recommends: {first.resolution}")
        resources = sum(len(results) for results in failing.values())
        lines.append(
            f"tofu-scan: {len(failing)} check id(s) reported, naming {resources} resource(s); "
            "an id in the ignore file is not reported"
        )
        return lines


def _line(metadata: dict[str, Any]) -> int | None:
    value = metadata.get("StartLine")
    return value if isinstance(value, int) and value > 0 else None


def parse_trivy_config(text: str) -> ScanResult:
    """Turn Trivy's configuration-scan JSON into check results, failures and passes alike."""
    try:
        document = json.loads(text)
    except ValueError as exc:
        raise ScanError(f"Trivy printed no JSON: {exc}") from exc
    results = document.get("Results") if isinstance(document, dict) else None
    found: list[CheckResult] = []
    for result in results if isinstance(results, list) else []:
        if not isinstance(result, dict):
            continue
        target = str(result.get("Target") or "").removeprefix(f"{SCAN_MOUNT}/")
        for item in result.get("Misconfigurations") or []:
            if not isinstance(item, dict):
                continue
            metadata = item.get("CauseMetadata")
            metadata = metadata if isinstance(metadata, dict) else {}
            found.append(
                CheckResult(
                    check_id=str(item.get("ID") or item.get("AVDID") or ""),
                    alias=str(item.get("AVDID") or ""),
                    status=str(item.get("Status") or FAIL).upper(),
                    severity=str(item.get("Severity") or "UNKNOWN").upper(),
                    title=str(item.get("Title") or "").strip(),
                    resolution=str(item.get("Resolution") or "").strip(),
                    resource=str(metadata.get("Resource") or target or "(the configuration)"),
                    target=target,
                    line=_line(metadata),
                )
            )
    return ScanResult(tuple(found))


@dataclass(frozen=True)
class IgnoreEntry:
    """One entry of ``.trivyignore``: the check id, its line, and the comment directly above it."""

    check_id: str
    line: int
    comment: str


def parse_ignore(text: str) -> list[IgnoreEntry]:
    """Return the entries of an ignore file, each with the comment line directly above it.

    A line is an entry when it is neither blank nor a ``#`` comment; its first word is the
    check id (Trivy allows an ``exp:`` date after it). The comment is the text of the line
    directly above the entry when that line is a comment with words in it, and empty otherwise.
    """
    entries: list[IgnoreEntry] = []
    previous = ""
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if line and not line.startswith("#"):
            comment = previous.lstrip("#").strip() if previous.startswith("#") else ""
            entries.append(IgnoreEntry(line.split()[0], number, comment))
        previous = line
    return entries


def scan_configuration(
    configuration: Path,
    ignore_text: str,
    *,
    root: Path = TASK_ROOT,
    runner: tofu.Runner = tofu.run_command,
) -> ScanResult:
    """Scan a copy of ``configuration``, ignoring the check ids ``ignore_text`` lists."""
    pins = scanners.load_pins(root)
    reference = pins.scanners["trivy"].reference
    with tempfile.TemporaryDirectory(prefix="coldline-tofu-scan-") as temporary:
        tree = Path(temporary) / "tree"
        ignore = Path(temporary) / "ignore"
        cache = Path(temporary) / "cache"
        ignore.mkdir()
        cache.mkdir()
        tofu.copy_configuration(configuration, tree)
        (tree / tofu.IGNORE_FILE).unlink(missing_ok=True)
        (ignore / IGNORE_NAME).write_text(trivy_ignore_text(ignore_text), encoding="utf-8")
        completed = runner(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                *tofu.user_flags(),
                "-v",
                f"{tree.resolve()}:{SCAN_MOUNT}:ro",
                "-v",
                f"{ignore.resolve()}:{IGNORE_MOUNT}:ro",
                "-v",
                f"{cache.resolve()}:/cache",
                reference,
                "--cache-dir",
                "/cache",
                "--quiet",
                "config",
                *TRIVY_CONFIG_FLAGS,
                "--ignorefile",
                f"{IGNORE_MOUNT}/{IGNORE_NAME}",
                "--format",
                "json",
                SCAN_MOUNT,
            ],
            True,
        )
    if completed.returncode != 0 or not (completed.stdout or "").strip():
        detail = tofu.tail(tofu.output_of(completed))
        raise ScanError(f"Trivy exited {completed.returncode}: {detail}")
    return parse_trivy_config(completed.stdout or "")


def read_ignore(configuration: Path) -> str:
    """Return the ignore file's text, or an empty text when there is none."""
    path = configuration / tofu.IGNORE_FILE
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def triage_problems(
    check_id: str,
    decision: str,
    entries: Sequence[IgnoreEntry],
    ignored: ScanResult,
    unignored: ScanResult,
) -> list[str]:
    """Return why a triage disagrees with the scan and the ignore file; empty when it agrees.

    ``ignored`` is the scan with your ignore file, ``unignored`` the same scan with an empty
    one. A fixed check id has no entry in the ignore file (which then holds none), no failing
    result, and at least one passing result: the check runs on what you declared and passes.
    An accepted check id is the ignore file's one entry, with a comment line directly above
    it; the scan without the ignore file reports it, and the scan with it does not.
    """
    problems: list[str] = []
    named = [entry for entry in entries if normalize(entry.check_id) == normalize(check_id)]
    still_failing = ignored.reports(check_id, FAIL)
    if decision == FIX:
        if entries:
            listed = ", ".join(entry.check_id for entry in entries)
            problems.append(
                f"a fixed check id needs no entry in infra/tofu/.trivyignore, which lists {listed}"
            )
        if still_failing:
            where = ", ".join(result.where for result in still_failing)
            problems.append(f"the scan still reports {check_id} on {where}")
        elif not unignored.reports(check_id, PASS):
            problems.append(
                f"the scan shows no resource you declared passing {check_id}: it is not a check "
                "the scan runs on your declarations"
            )
    elif decision == ACCEPT:
        if len(entries) != 1 or not named:
            listed = ", ".join(entry.check_id for entry in entries) or "nothing"
            problems.append(
                "an accepted check id is the one entry in infra/tofu/.trivyignore; it lists "
                f"{listed}"
            )
        elif not named[0].comment:
            problems.append(
                f"the entry for {check_id} (line {named[0].line}) needs a comment line directly "
                "above it saying why it is safe here and what would make it unsafe"
            )
        if not unignored.reports(check_id, FAIL):
            problems.append(f"without the ignore file the scan does not report {check_id}")
        if still_failing:
            problems.append(f"with the ignore file the scan still reports {check_id}")
    else:
        problems.append(f"the triage decision is `{FIX}` or `{ACCEPT}`, not {decision!r}")
    return problems


def main(argv: list[str] | None = None) -> int:
    """Scan infra/tofu/ with its ignore file and print what the scan reports."""
    parser = argparse.ArgumentParser(
        description="Run Trivy's configuration scan over infra/tofu/ with its ignore file."
    )
    parser.add_argument("--root", type=Path, default=TASK_ROOT)
    arguments = parser.parse_args(argv)
    root = arguments.root.resolve()
    configuration = root / tofu.TOFU_DIRECTORY
    ignore_text = read_ignore(configuration)
    entries = parse_ignore(ignore_text)
    label = f"ignore file infra/tofu/.trivyignore, {len(entries)} entry line(s)"
    try:
        trivy = scanners.load_pins(root).scanners["trivy"].reference
        missing = tofu.setup_problem(root, [trivy], provider=False)
        if missing is not None:
            raise ScanError(missing)
        result = scan_configuration(configuration, ignore_text, root=root)
    except (ScanError, scanners.ScanError, tofu.TofuError) as exc:
        print(f"tofu-scan: {exc}", file=sys.stderr)
        return 2
    for line in result.lines(label):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
