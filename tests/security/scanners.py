"""Coldline.

===================

File:              tests/security/scanners.py
Component:         Security tooling — The three pinned scanners
Purpose:           Run Semgrep, Trivy and Gitleaks, pinned by digest, over a copy of a tree with
                    the network off, turn their output into findings with stable ids, judge them
                    against the gate's thresholds, and write the scan report and the software bill
                    of materials.
Interacts With:    security/scanners.yaml, security/semgrep-rules.yaml, .gitleaks.toml,
                    security/gate.yaml, tests/security/gate.py, tests/security/repository.py,
                    tests/security/seeds.py, tests/security/security_scan.py,
                    tests/security/security_setup.py, tests/contract/test_security_contract.py,
                    .github/workflows/security.yml
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          Pinned tools, offline scans, content-derived finding ids, one severity scale,
                    reports as evidence
Tools:             Python 3.12, Docker, Semgrep, Trivy, Gitleaks, SARIF, CycloneDX

**What is scanned.** Never the checkout itself: ``copy_tree_for_scan`` copies the files Git
tracks or would track (``repository.listed_files``: tracked plus untracked files no ignore
rule covers) into a temporary directory, which is what the gate sees at a pull request's
head, with the virtual environment, the tool cache and the generated reports left out and
an uncommitted seed file included. ``scan_baseline`` exports the starting checkpoint
(``repository.export_baseline``) the same way; ``scan_seeded`` applies one seed to a copy.
Each scanner runs through ``docker run --rm --network none`` with the copy mounted
read-only at ``/scan``.

**The scanners.** Semgrep with the supplied local rules only, metrics off, rule ids not
rewritten, inline ``nosemgrep`` markers not honoured; Gitleaks in ``dir`` mode over the copy
with a configuration mounted beside it
(the student's ``.gitleaks.toml``, or the supplied inventory configuration, the default
rules plus the supplied provider-key rule and no allowlist, when a caller asks for every
finding regardless of suppressions); Trivy over the copy with the vulnerability database
pinned in ``security/scanners.yaml``, downloaded once by ``ensure_trivy_database`` into the
ignored cache, and every scan run with ``--skip-db-update --skip-java-db-update
--offline-scan``.

**Findings and ids.** One finding is one rule reported in one file: a Semgrep rule in one
file (every match line listed), a Gitleaks rule in one file (every match line listed), a
Trivy vulnerability of one package in one target. The id is ``F-`` and the last
``ID_DIGITS`` (two) decimal digits of the SHA-256 of ``scanner|rule|path``, so it depends
on what the finding is and not on where in the file it is or what else the tree holds; a
finding keeps its id across edits, machines, the hosted job, and across the baseline, the
inventory, the clean and the seeded reports, whatever else each of them holds. The width
is fixed: when two findings of one report share an id, ``finding_ids`` raises a
``ScanError`` naming both, which is the course team's signal to widen ``ID_DIGITS``
everywhere (the key, the schema and the sheets with it), never a per-report change of one
finding's id. Ids sort numerically. Severities are on the gate's scale
(``tests/security/gate.py``): Trivy's directly, Semgrep's INFO, WARNING and ERROR as low,
medium and high, and a Gitleaks finding is a ``secret``.

**The database cache.** ``ensure_trivy_database`` keeps the pinned database under
``.tools/trivy-cache/<digest prefix>/`` (the first twelve hex characters of the pinned
digest) beside a marker file that records the full pinned reference. A cache whose marker
is missing or names another digest is no cache: the database is downloaded again into the
directory the pinned digest names, so a re-pin never reuses the old snapshot under the new
name.

**Reports.** ``write_reports`` writes ``reports/security/scan.sarif`` (SARIF 2.1.0, one run
per scanner, every finding with its id and whether it fails the gate, and, when the caller
knows it, the scanned commit as each run's version-control provenance) and
``reports/security/sbom.cdx.json`` (CycloneDX, from Trivy over the same copy). Nothing in a
report or on the terminal repeats a matched secret: Gitleaks runs with ``--redact``, and the
findings carry rule, file and line. Neither scanner honours an inline marker: Semgrep runs
with ``--disable-nosem`` and Gitleaks with ``--ignore-gitleaks-allow``, so a finding leaves
the report when the construct leaves the file or a reviewed suppression covers it.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from tests.security import gate, repository, seeds
from tests.security.gate import Thresholds

TASK_ROOT = Path(__file__).resolve().parents[2]
PINS_PATH = Path("security/scanners.yaml")
SEMGREP_RULES = Path("security/semgrep-rules.yaml")
GITLEAKS_CONFIG = Path(".gitleaks.toml")
REPORTS_DIRECTORY = Path("reports/security")
SARIF_NAME = "scan.sarif"
SBOM_NAME = "sbom.cdx.json"
SCAN_MOUNT = "/scan"
DOCKER_TIMEOUT_SECONDS = 1800
SCANNERS: tuple[str, ...] = ("semgrep", "gitleaks", "trivy")
SEMGREP_SEVERITIES: dict[str, str] = {"INFO": "low", "WARNING": "medium", "ERROR": "high"}
TRIVY_SEVERITIES: dict[str, str] = {
    "UNKNOWN": "low",
    "LOW": "low",
    "MEDIUM": "medium",
    "HIGH": "high",
    "CRITICAL": "critical",
}
SARIF_LEVELS: dict[str, str] = {
    "low": "note",
    "medium": "warning",
    "high": "error",
    "critical": "error",
    gate.SECRET: "error",
}
ID_PREFIX = "F-"
# Fixed width. Widening it is a course-team change made everywhere at once (the key, the
# answer schema, the sheets, the suppression comment), never by one report.
ID_DIGITS = 2
# The marker file beside a cached database, holding the pinned reference it was downloaded
# from; the cache directory itself is named by the digest's first characters.
DATABASE_MARKER = "pinned-database.txt"
DATABASE_PREFIX_CHARACTERS = 12
SUPPLIED_GITLEAKS_RULE_ID = seeds.SUPPLIED_RULE_ID
SUPPLIED_GITLEAKS_RULE_REGEX = seeds.SUPPLIED_RULE_REGEX
# The inventory configuration: the default rules plus the supplied provider-key rule, and
# no allowlist. The student's .gitleaks.toml is this text plus one allowlist entry.
SUPPLIED_GITLEAKS_CONFIG = (
    'title = "Coldline secret-scanner configuration (inventory)"\n'
    "\n"
    "[extend]\n"
    "useDefault = true\n"
    "\n"
    "[[rules]]\n"
    f'id = "{SUPPLIED_GITLEAKS_RULE_ID}"\n'
    'description = "Coldline model-provider key"\n'
    f"regex = '''{SUPPLIED_GITLEAKS_RULE_REGEX}'''\n"
    'keywords = ["cpk_"]\n'
)
# Directories never copied into a scan tree when the tree is not a repository.
IGNORED_DIRECTORIES: frozenset[str] = frozenset(
    {
        ".git",
        ".venv",
        ".tools",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
        "reports",
        "evidence",
        ".benchmark",
        "node_modules",
    }
)
Runner = Callable[[list[str]], subprocess.CompletedProcess[str]]


class ScanError(RuntimeError):
    """Report that a scanner could not run or answer, as opposed to a finding."""


# --- Pins ---------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Pin:
    """One scanner image, pinned by digest, with its version recorded for a reader."""

    name: str
    image: str
    version: str
    digest: str

    @property
    def reference(self) -> str:
        """Return the image reference Docker pulls: the digest, with the tag beside it."""
        return f"{self.image}:{self.version}@{self.digest}"


@dataclass(frozen=True)
class TrivyDatabase:
    """The pinned vulnerability database: where it comes from, its digest, the cache."""

    repository: str
    digest: str
    cache: Path
    ignore_unfixed: bool

    @property
    def reference(self) -> str:
        """Return the database's OCI reference by digest."""
        return f"{self.repository}@{self.digest}"

    @property
    def cache_name(self) -> str:
        """Return the cache directory this digest's database lives in, under ``cache``."""
        return self.digest.removeprefix("sha256:")[:DATABASE_PREFIX_CHARACTERS]

    def cache_for(self, root: Path) -> Path:
        """Return the directory the pinned database is cached in under ``root``."""
        return root / self.cache / self.cache_name


@dataclass(frozen=True)
class Pins:
    """Every pin security/scanners.yaml declares."""

    scanners: Mapping[str, Pin]
    trivy_db: TrivyDatabase


def load_pins(root: Path = TASK_ROOT) -> Pins:
    """Read security/scanners.yaml."""
    path = root / PINS_PATH
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ScanError(f"{PINS_PATH.as_posix()} could not be read: {exc}") from exc
    if not isinstance(document, dict):
        raise ScanError(f"{PINS_PATH.as_posix()} must be one mapping")
    scanners_section = document.get("scanners")
    database = document.get("trivy_db")
    if not isinstance(scanners_section, dict) or not isinstance(database, dict):
        raise ScanError(f"{PINS_PATH.as_posix()} must hold `scanners` and `trivy_db`")
    pins: dict[str, Pin] = {}
    for name in SCANNERS:
        entry = scanners_section.get(name)
        if not isinstance(entry, dict):
            raise ScanError(f"{PINS_PATH.as_posix()} pins no `{name}` image")
        image, version, digest = entry.get("image"), entry.get("version"), entry.get("digest")
        if not all(isinstance(value, str) and value for value in (image, version, digest)):
            raise ScanError(f"{PINS_PATH.as_posix()}: `{name}` needs image, version and digest")
        if not str(digest).startswith("sha256:"):
            raise ScanError(f"{PINS_PATH.as_posix()}: `{name}` is not pinned by a sha256 digest")
        pins[name] = Pin(name, str(image), str(version), str(digest))
    repository_name = database.get("repository")
    database_digest = database.get("digest")
    cache = database.get("cache")
    database_fields = (repository_name, database_digest, cache)
    if not all(isinstance(value, str) and value for value in database_fields):
        raise ScanError(f"{PINS_PATH.as_posix()}: `trivy_db` needs repository, digest and cache")
    if not str(database_digest).startswith("sha256:"):
        raise ScanError(f"{PINS_PATH.as_posix()}: the Trivy database is not pinned by a digest")
    ignore_unfixed = database.get("ignore_unfixed", False)
    if not isinstance(ignore_unfixed, bool):
        raise ScanError(f"{PINS_PATH.as_posix()}: `trivy_db.ignore_unfixed` must be true or false")
    return Pins(
        pins,
        TrivyDatabase(str(repository_name), str(database_digest), Path(str(cache)), ignore_unfixed),
    )


# --- Findings -----------------------------------------------------------------------------------


@dataclass(frozen=True)
class Match:
    """One place a finding's rule matched: the line (when the scanner gives one) and a label."""

    line: int | None
    detail: str


@dataclass(frozen=True)
class Finding:
    """One rule reported in one file by one scanner, at one severity on the gate's scale."""

    scanner: str
    rule: str
    path: str
    severity: str
    title: str
    matches: tuple[Match, ...] = ()

    @property
    def key(self) -> str:
        """Return what the id is derived from: the scanner, the rule and the path."""
        return f"{self.scanner}|{self.rule}|{self.path}"

    @property
    def lines(self) -> tuple[int, ...]:
        """Return the matched lines, in order, without the matches that have none."""
        return tuple(match.line for match in self.matches if match.line is not None)


def finding_id(key: str) -> str:
    """Return the id of one key: ``F-`` and the last ``ID_DIGITS`` decimal digits of its digest."""
    value = int(hashlib.sha256(key.encode("utf-8")).hexdigest(), 16)
    return f"{ID_PREFIX}{value % (10**ID_DIGITS):0{ID_DIGITS}d}"


def id_order(identifier: str) -> int:
    """Return the numeric value of an id, so ids sort as numbers."""
    return int(identifier[len(ID_PREFIX) :])


def finding_ids(findings: Sequence[Finding]) -> dict[str, str]:
    """Return every finding's id by its key; two keys with one id are an error, never widened."""
    keys = sorted({finding.key for finding in findings})
    ids = {key: finding_id(key) for key in keys}
    groups: dict[str, list[str]] = {}
    for key, identity in ids.items():
        groups.setdefault(identity, []).append(key)
    collided = sorted(group for group in groups.values() if len(group) > 1)
    if collided:
        described = "; ".join(
            f"{finding_id(group[0])} is the id of both {' and '.join(group)}" for group in collided
        )
        raise ScanError(
            f"two findings share one {ID_DIGITS}-digit id ({described}); the id width is fixed "
            "so that every finding keeps its id across reports, and widening it is a course-team "
            "change made everywhere at once (docs/security/gate-policy.md); report this to the "
            "course"
        )
    return ids


def _relative(path: str) -> str:
    """Return a scanner's path relative to the scan root, however the scanner printed it."""
    text = path.replace("\\", "/")
    for prefix in (f"{SCAN_MOUNT}/", f"{SCAN_MOUNT.lstrip('/')}/", "./"):
        if text.startswith(prefix):
            text = text[len(prefix) :]
    return text


def parse_semgrep(text: str) -> list[Finding]:
    """Turn Semgrep's JSON into findings: one per (rule, file), every match line listed."""
    try:
        document = json.loads(text)
    except ValueError as exc:
        raise ScanError(f"Semgrep printed no JSON: {exc}") from exc
    errors = document.get("errors") if isinstance(document, dict) else None
    fatal = [
        error
        for error in (errors or [])
        if isinstance(error, dict) and str(error.get("level", "")).lower() == "error"
    ]
    if fatal:
        first = fatal[0]
        raise ScanError(f"Semgrep reported an error: {first.get('message') or first}")
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for result in document.get("results", []) if isinstance(document, dict) else []:
        if not isinstance(result, dict):
            continue
        rule = str(result.get("check_id", ""))
        path = _relative(str(result.get("path", "")))
        grouped.setdefault((rule, path), []).append(result)
    findings: list[Finding] = []
    for (rule, path), results in grouped.items():
        extra = results[0].get("extra", {}) if isinstance(results[0].get("extra"), dict) else {}
        severity = SEMGREP_SEVERITIES.get(str(extra.get("severity", "")).upper(), "low")
        title = str(extra.get("message", rule)).strip().split("\n")[0]
        matches = tuple(
            Match(_line_of(item.get("start")), "match")
            for item in sorted(results, key=lambda item: _line_of(item.get("start")) or 0)
        )
        findings.append(Finding("semgrep", rule, path, severity, title, matches))
    return findings


def _line_of(position: object) -> int | None:
    if isinstance(position, dict):
        line = position.get("line")
        if isinstance(line, int):
            return line
    if isinstance(position, int):
        return position
    return None


def parse_gitleaks(text: str) -> list[Finding]:
    """Turn Gitleaks' JSON report into findings: one per (rule, file), every match line listed."""
    stripped = text.strip()
    if not stripped:
        return []
    try:
        document = json.loads(stripped)
    except ValueError as exc:
        raise ScanError(f"Gitleaks printed no JSON: {exc}") from exc
    if not isinstance(document, list):
        raise ScanError("Gitleaks' report is not a list of findings")
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for item in document:
        if not isinstance(item, dict):
            continue
        rule = str(item.get("RuleID", ""))
        path = _relative(str(item.get("File", "")))
        grouped.setdefault((rule, path), []).append(item)
    findings: list[Finding] = []
    for (rule, path), items in grouped.items():
        title = str(items[0].get("Description") or rule)
        matches = tuple(
            Match(_line_of(item.get("StartLine")), "match")
            for item in sorted(items, key=lambda item: _line_of(item.get("StartLine")) or 0)
        )
        findings.append(Finding("gitleaks", rule, path, gate.SECRET, title, matches))
    return findings


def parse_trivy(text: str, *, ignore_unfixed: bool = False) -> list[Finding]:
    """Turn Trivy's JSON into findings: one per (vulnerability, package, target)."""
    try:
        document = json.loads(text)
    except ValueError as exc:
        raise ScanError(f"Trivy printed no JSON: {exc}") from exc
    results = document.get("Results") if isinstance(document, dict) else None
    findings: list[Finding] = []
    for result in results or []:
        if not isinstance(result, dict):
            continue
        target = _relative(str(result.get("Target", "")))
        for item in result.get("Vulnerabilities") or []:
            if not isinstance(item, dict):
                continue
            fixed = str(item.get("FixedVersion") or "")
            if ignore_unfixed and not fixed:
                continue
            identifier = str(item.get("VulnerabilityID", ""))
            package = str(item.get("PkgName", ""))
            installed = str(item.get("InstalledVersion", ""))
            severity = TRIVY_SEVERITIES.get(str(item.get("Severity", "")).upper(), "low")
            title = str(item.get("Title") or identifier).strip()
            fix = f"fixed in {fixed}" if fixed else "no fixed version"
            detail = f"{package}@{installed}, {fix}"
            findings.append(
                Finding(
                    "trivy",
                    f"{identifier}:{package}",
                    target,
                    severity,
                    f"{package} {installed}: {title}",
                    (Match(None, detail),),
                )
            )
    return findings


# --- The report ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class Report:
    """One scan: what was scanned, the thresholds, the findings with their ids, the raw outputs."""

    label: str
    thresholds: Thresholds
    findings: tuple[Finding, ...]
    ids: Mapping[str, str]
    versions: Mapping[str, str]
    outputs: Mapping[str, str]
    sbom: str | None = None

    def id_of(self, finding: Finding) -> str:
        """Return one finding's id."""
        return self.ids[finding.key]

    def by_id(self) -> dict[str, Finding]:
        """Return the findings keyed by id."""
        return {self.id_of(finding): finding for finding in self.findings}

    def finding(self, finding_id: str) -> Finding | None:
        """Return the finding with the given id, or None."""
        return self.by_id().get(finding_id)

    def path_of(self, finding_id: str) -> str | None:
        """Return the file the finding with the given id names, or None."""
        found = self.finding(finding_id)
        return None if found is None else found.path

    def fails(self, finding: Finding) -> bool:
        """Return whether a finding is at or above its scanner's threshold."""
        return self.thresholds.fails(finding.scanner, finding.severity)

    def _order(self, finding: Finding) -> int:
        return id_order(self.id_of(finding))

    @property
    def failing(self) -> tuple[Finding, ...]:
        """Return the findings at or above their thresholds, in numeric id order."""
        return tuple(sorted((f for f in self.findings if self.fails(f)), key=self._order))

    @property
    def passed(self) -> bool:
        """Return whether the gate passes: no finding at or above a threshold."""
        return not self.failing

    def sorted(self) -> list[Finding]:
        """Return every finding in numeric id order."""
        return sorted(self.findings, key=self._order)

    def lines(self) -> list[str]:
        """Render the scan for the terminal: every finding, the marks, the verdict."""
        count = len(self.findings)
        lines = [
            f"security-scan: {count} finding(s) on {self.label} "
            f"(thresholds: {self.thresholds.describe()})"
        ]
        for finding in self.sorted():
            mark = "!" if self.fails(finding) else " "
            where = finding.path
            if finding.lines:
                where += ":" + ",".join(str(line) for line in finding.lines)
            extra = ""
            if finding.scanner == "trivy" and finding.matches:
                extra = f"  {finding.matches[0].detail}"
            elif len(finding.matches) > 1:
                extra = f"  ({len(finding.matches)} matches)"
            lines.append(
                f"  {mark} {self.id_of(finding):<7} {finding.scanner:<8} {finding.severity:<8} "
                f"{where}  {finding.rule}{extra}"
            )
        if count:
            lines.append("  (a `!` marks a finding at or above its threshold)")
        if self.passed:
            lines.append("gate: passed (no unsuppressed finding at or above a threshold)")
        else:
            named = ", ".join(self.id_of(finding) for finding in self.failing)
            lines.append(
                f"gate: failed ({len(self.failing)} finding(s) at or above a threshold: {named})"
            )
        return lines

    def as_document(self) -> dict[str, Any]:
        """Return the report as JSON-ready data (ids, findings, verdict), for `--json`."""
        return {
            "label": self.label,
            "thresholds": {key: self.thresholds.value(key) for key in gate.KEYS},
            "passed": self.passed,
            "failing": [self.id_of(finding) for finding in self.failing],
            "findings": [
                {
                    "id": self.id_of(finding),
                    "scanner": finding.scanner,
                    "rule": finding.rule,
                    "path": finding.path,
                    "severity": finding.severity,
                    "title": finding.title,
                    "lines": list(finding.lines),
                    "fails": self.fails(finding),
                }
                for finding in self.sorted()
            ],
        }


def sarif(report: Report, revision: str | None = None) -> dict[str, Any]:
    """Return the report as a SARIF 2.1.0 document: one run per scanner.

    ``revision`` is the commit whose files were scanned, when the caller knows it (the
    hosted job passes the checked-out pull-request head); it is recorded as each run's
    ``versionControlProvenance`` and under ``coldline/revision``, so the report says which
    tree it judged.
    """
    runs: list[dict[str, Any]] = []
    for scanner in SCANNERS:
        findings = [finding for finding in report.sorted() if finding.scanner == scanner]
        rules: dict[str, dict[str, Any]] = {}
        results: list[dict[str, Any]] = []
        for finding in findings:
            rules.setdefault(
                finding.rule,
                {"id": finding.rule, "shortDescription": {"text": finding.title[:200]}},
            )
            locations = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.path},
                        **({"region": {"startLine": match.line}} if match.line is not None else {}),
                    }
                }
                for match in (finding.matches or (Match(None, ""),))
            ]
            results.append(
                {
                    "ruleId": finding.rule,
                    "level": SARIF_LEVELS.get(finding.severity, "warning"),
                    "message": {"text": f"{report.id_of(finding)}: {finding.title}"},
                    "locations": locations,
                    "properties": {
                        "coldline/findingId": report.id_of(finding),
                        "coldline/severity": finding.severity,
                        "coldline/failsGate": report.fails(finding),
                    },
                }
            )
        run: dict[str, Any] = {
            "tool": {
                "driver": {
                    "name": scanner,
                    "version": report.versions.get(scanner, ""),
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "properties": {
                "coldline/thresholds": {k: report.thresholds.value(k) for k in gate.KEYS},
                "coldline/scanned": report.label,
            },
        }
        if revision is not None:
            run["versionControlProvenance"] = [{"revisionId": revision}]
            run["properties"]["coldline/revision"] = revision
        runs.append(run)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": runs,
    }


def write_reports(
    report: Report, directory: Path, *, revision: str | None = None
) -> tuple[Path, Path]:
    """Write scan.sarif and sbom.cdx.json under ``directory``; return both paths.

    ``revision`` is recorded in the SARIF report as the scanned commit when given.
    """
    if report.sbom is None:
        raise ScanError("the scan was run without the software bill of materials; nothing to write")
    directory.mkdir(parents=True, exist_ok=True)
    sarif_path = directory / SARIF_NAME
    sbom_path = directory / SBOM_NAME
    document = sarif(report, revision)
    sarif_path.write_text(json.dumps(document, indent=2, sort_keys=True), encoding="utf-8")
    sbom_path.write_text(report.sbom, encoding="utf-8")
    return sarif_path, sbom_path


# --- Running the scanners -----------------------------------------------------------------------


def run_docker(arguments: list[str]) -> subprocess.CompletedProcess[str]:
    """Run one ``docker`` command and return it, output captured."""
    try:
        return subprocess.run(
            ["docker", *arguments],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=DOCKER_TIMEOUT_SECONDS,
        )
    except FileNotFoundError as exc:
        raise ScanError("docker is not on PATH; the scanners run through Docker") from exc
    except subprocess.TimeoutExpired as exc:
        raise ScanError(f"docker did not finish within {DOCKER_TIMEOUT_SECONDS} s: {exc}") from exc


def _user_flags() -> list[str]:
    """Return ``--user uid:gid`` on POSIX, so files a scanner writes are the caller's."""
    getuid = getattr(os, "getuid", None)
    getgid = getattr(os, "getgid", None)
    if getuid is None or getgid is None:
        return []
    return ["--user", f"{getuid()}:{getgid()}"]


def _mount(path: Path) -> str:
    return str(path.resolve())


def _tail(text: str, lines: int = 12) -> str:
    return "\n".join(text.strip().splitlines()[-lines:])


def cached_database(cache: Path, database: TrivyDatabase) -> bool:
    """Return whether ``cache`` holds the pinned database: a marker naming the pin, and the db.

    A cache with a database but no marker, or a marker naming another reference, is no
    cache: it was downloaded for a different pin (or before markers were written), and
    reusing it would announce one digest while scanning with another.
    """
    marker = cache / DATABASE_MARKER
    if not marker.is_file() or not (cache / "db" / "metadata.json").is_file():
        return False
    try:
        return marker.read_text(encoding="utf-8").strip() == database.reference
    except OSError:
        return False


def ensure_trivy_database(
    root: Path = TASK_ROOT, *, runner: Runner = run_docker, pins: Pins | None = None
) -> Path:
    """Download the pinned vulnerability database once into its digest-named cache; return it."""
    pins = load_pins(root) if pins is None else pins
    database = pins.trivy_db
    cache = database.cache_for(root)
    if cached_database(cache, database):
        return cache
    # Whatever is there belongs to no pin this file knows: start the directory over.
    shutil.rmtree(cache / "db", ignore_errors=True)
    (cache / DATABASE_MARKER).unlink(missing_ok=True)
    cache.mkdir(parents=True, exist_ok=True)
    completed = runner(
        [
            "run",
            "--rm",
            *_user_flags(),
            "-v",
            f"{_mount(cache)}:/cache",
            pins.scanners["trivy"].reference,
            "--cache-dir",
            "/cache",
            "--quiet",
            "image",
            "--download-db-only",
            "--db-repository",
            pins.trivy_db.reference,
            "--skip-java-db-update",
        ]
    )
    if completed.returncode != 0 or not (cache / "db" / "metadata.json").is_file():
        raise ScanError(
            "the pinned Trivy database could not be downloaded "
            f"({database.reference}): {_tail(completed.stderr or completed.stdout)}\n"
            "If the registry no longer serves this digest, the re-pin step in "
            "docs/security/gate-policy.md applies; it is the course team's change, not yours."
        )
    (cache / DATABASE_MARKER).write_text(database.reference + "\n", encoding="utf-8")
    return cache


def pull_images(root: Path = TASK_ROOT, *, runner: Runner = run_docker) -> list[str]:
    """Pull the three pinned scanner images; return the references pulled."""
    pins = load_pins(root)
    pulled: list[str] = []
    for name in SCANNERS:
        reference = pins.scanners[name].reference
        completed = runner(["pull", "--quiet", reference])
        if completed.returncode != 0:
            raise ScanError(f"{reference} could not be pulled: {_tail(completed.stderr)}")
        pulled.append(reference)
    return pulled


def _run_semgrep(tree: Path, pins: Pins, runner: Runner) -> str:
    completed = runner(
        [
            "run",
            "--rm",
            "--network",
            "none",
            "-e",
            "SEMGREP_SEND_METRICS=off",
            "-v",
            f"{_mount(tree)}:{SCAN_MOUNT}:ro",
            "-w",
            SCAN_MOUNT,
            pins.scanners["semgrep"].reference,
            "semgrep",
            "scan",
            "--config",
            SEMGREP_RULES.as_posix(),
            "--json",
            "--metrics=off",
            "--disable-version-check",
            "--no-rewrite-rule-ids",
            # Inline `nosemgrep` comments are not honoured: a finding leaves the report when
            # the construct leaves the file, never because a marker was written beside it.
            "--disable-nosem",
            "--quiet",
            ".",
        ]
    )
    if completed.returncode not in {0, 1} or not completed.stdout.strip():
        raise ScanError(f"Semgrep exited {completed.returncode}: {_tail(completed.stderr)}")
    return completed.stdout


def _run_gitleaks(tree: Path, config_dir: Path, out: Path, pins: Pins, runner: Runner) -> str:
    completed = runner(
        [
            "run",
            "--rm",
            "--network",
            "none",
            *_user_flags(),
            "-v",
            f"{_mount(tree)}:{SCAN_MOUNT}:ro",
            "-v",
            f"{_mount(config_dir)}:/config:ro",
            "-v",
            f"{_mount(out)}:/out",
            # Gitleaks matches an allowlist's `paths` against the path it reports; scanning `.`
            # from inside the mount makes that the repository-relative path a student writes.
            "-w",
            SCAN_MOUNT,
            pins.scanners["gitleaks"].reference,
            "dir",
            ".",
            "--config",
            "/config/gitleaks.toml",
            "--report-format",
            "json",
            "--report-path",
            "/out/gitleaks.json",
            "--exit-code",
            "0",
            "--no-banner",
            "--redact",
            # An inline `gitleaks:allow` comment beside a match is not a reviewed
            # suppression: the one allowlist entry in `.gitleaks.toml` is, so the marker
            # hides nothing, in the ordinary scan and in the inventory scan alike.
            "--ignore-gitleaks-allow",
            "--log-level",
            "error",
        ]
    )
    report = out / "gitleaks.json"
    if completed.returncode != 0 or not report.is_file():
        raise ScanError(f"Gitleaks exited {completed.returncode}: {_tail(completed.stderr)}")
    return report.read_text(encoding="utf-8")


def _trivy_arguments(cache: Path, pins: Pins) -> list[str]:
    return [
        pins.scanners["trivy"].reference,
        "--cache-dir",
        "/cache",
        "--quiet",
        "fs",
        "--skip-db-update",
        "--skip-java-db-update",
        "--offline-scan",
        "--include-dev-deps",
    ]


def _run_trivy(tree: Path, cache: Path, out: Path, pins: Pins, runner: Runner) -> str:
    extra = ["--ignore-unfixed"] if pins.trivy_db.ignore_unfixed else []
    completed = runner(
        [
            "run",
            "--rm",
            "--network",
            "none",
            *_user_flags(),
            "-v",
            f"{_mount(tree)}:{SCAN_MOUNT}:ro",
            "-v",
            f"{_mount(cache)}:/cache",
            "-v",
            f"{_mount(out)}:/out",
            *_trivy_arguments(cache, pins),
            "--scanners",
            "vuln",
            *extra,
            "--format",
            "json",
            "--output",
            "/out/trivy.json",
            SCAN_MOUNT,
        ]
    )
    report = out / "trivy.json"
    if completed.returncode != 0 or not report.is_file():
        raise ScanError(f"Trivy exited {completed.returncode}: {_tail(completed.stderr)}")
    return report.read_text(encoding="utf-8")


def _run_sbom(tree: Path, cache: Path, out: Path, pins: Pins, runner: Runner) -> str:
    completed = runner(
        [
            "run",
            "--rm",
            "--network",
            "none",
            *_user_flags(),
            "-v",
            f"{_mount(tree)}:{SCAN_MOUNT}:ro",
            "-v",
            f"{_mount(cache)}:/cache",
            "-v",
            f"{_mount(out)}:/out",
            *_trivy_arguments(cache, pins),
            "--format",
            "cyclonedx",
            "--output",
            f"/out/{SBOM_NAME}",
            SCAN_MOUNT,
        ]
    )
    report = out / SBOM_NAME
    if completed.returncode != 0 or not report.is_file():
        raise ScanError(
            f"Trivy could not write the software bill of materials (exit {completed.returncode}): "
            f"{_tail(completed.stderr)}"
        )
    return report.read_text(encoding="utf-8")


def copy_tree_for_scan(root: Path, destination: Path) -> list[str]:
    """Copy the files the gate scans from ``root`` into ``destination``; return their paths.

    The files Git tracks or would track when ``root`` is a repository; otherwise every
    file outside ``IGNORED_DIRECTORIES``.
    """
    listed = repository.listed_files(root)
    if listed is None:
        listed = []
        for path in sorted(root.rglob("*")):
            found = path.relative_to(root)
            if not path.is_file() or IGNORED_DIRECTORIES & set(found.parts):
                continue
            listed.append(found.as_posix())
    copied: list[str] = []
    for relative in listed:
        source = root / relative
        if not source.is_file():
            continue
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        copied.append(relative)
    return copied


def tree_files(root: Path) -> list[str]:
    """Return the paths the gate scans under ``root`` without copying them."""
    listed = repository.listed_files(root)
    if listed is not None:
        return [relative for relative in listed if (root / relative).is_file()]
    return [
        path.relative_to(root).as_posix()
        for path in sorted(root.rglob("*"))
        if path.is_file() and not (IGNORED_DIRECTORIES & set(path.relative_to(root).parts))
    ]


def scan(
    tree: Path,
    *,
    root: Path = TASK_ROOT,
    thresholds: Thresholds,
    gitleaks_config: Path | None = None,
    runner: Runner = run_docker,
    label: str = "the working tree",
    sbom: bool = False,
) -> Report:
    """Run the three scanners over ``tree`` (a copy, mounted read-only) and judge the findings.

    ``gitleaks_config`` is the configuration Gitleaks applies (the student's file); None
    runs the supplied inventory configuration, which has no allowlist, so every secret
    finding is reported whether or not the student suppressed it.
    """
    pins = load_pins(root)
    cache = ensure_trivy_database(root, runner=runner, pins=pins)
    with tempfile.TemporaryDirectory(prefix="coldline-scan-") as temporary:
        out = Path(temporary) / "out"
        out.mkdir()
        config_dir = Path(temporary) / "config"
        config_dir.mkdir()
        configuration = (
            SUPPLIED_GITLEAKS_CONFIG
            if gitleaks_config is None
            else gitleaks_config.read_text(encoding="utf-8")
        )
        (config_dir / "gitleaks.toml").write_text(configuration, encoding="utf-8")
        semgrep_text = _run_semgrep(tree, pins, runner)
        gitleaks_text = _run_gitleaks(tree, config_dir, out, pins, runner)
        trivy_text = _run_trivy(tree, cache, out, pins, runner)
        sbom_text = _run_sbom(tree, cache, out, pins, runner) if sbom else None
    findings = (
        *parse_semgrep(semgrep_text),
        *parse_gitleaks(gitleaks_text),
        *parse_trivy(trivy_text, ignore_unfixed=pins.trivy_db.ignore_unfixed),
    )
    return Report(
        label,
        thresholds,
        tuple(findings),
        finding_ids(findings),
        {name: pins.scanners[name].version for name in SCANNERS},
        {"semgrep": semgrep_text, "gitleaks": gitleaks_text, "trivy": trivy_text},
        sbom_text,
    )


def scan_working_tree(
    root: Path = TASK_ROOT,
    thresholds: Thresholds | None = None,
    *,
    inventory: bool = False,
    runner: Runner = run_docker,
    sbom: bool = False,
) -> Report:
    """Scan a copy of the working tree with the student's thresholds and configuration.

    ``inventory`` applies the supplied Gitleaks configuration instead of the student's.
    """
    thresholds = gate.load_thresholds(root=root) if thresholds is None else thresholds
    with tempfile.TemporaryDirectory(prefix="coldline-tree-") as temporary:
        copy = Path(temporary) / "tree"
        copy.mkdir()
        copy_tree_for_scan(root, copy)
        return scan(
            copy,
            root=root,
            thresholds=thresholds,
            gitleaks_config=None if inventory else copy / GITLEAKS_CONFIG,
            runner=runner,
            label="the working tree" + (" (inventory, no allowlist applied)" if inventory else ""),
            sbom=sbom,
        )


def scan_seeded(
    kind: str,
    root: Path = TASK_ROOT,
    thresholds: Thresholds | None = None,
    *,
    runner: Runner = run_docker,
) -> Report:
    """Scan a copy of the working tree with one seed applied, under the student's configuration."""
    thresholds = gate.load_thresholds(root=root) if thresholds is None else thresholds
    with tempfile.TemporaryDirectory(prefix="coldline-seeded-") as temporary:
        copy = Path(temporary) / "tree"
        copy.mkdir()
        copy_tree_for_scan(root, copy)
        seeds.apply(kind, copy)
        return scan(
            copy,
            root=root,
            thresholds=thresholds,
            gitleaks_config=copy / GITLEAKS_CONFIG,
            runner=runner,
            label=f"a copy with the {kind} seed applied",
        )


def scan_baseline(
    root: Path = TASK_ROOT, thresholds: Thresholds | None = None, *, runner: Runner = run_docker
) -> Report:
    """Scan the starting checkpoint (the merge base) with the inventory configuration."""
    thresholds = gate.load_thresholds(root=root) if thresholds is None else thresholds
    with tempfile.TemporaryDirectory(prefix="coldline-baseline-tree-") as temporary:
        copy = Path(temporary) / "tree"
        try:
            commit = repository.export_baseline(root, copy)
        except repository.RepositoryError as exc:
            raise ScanError(str(exc)) from exc
        return scan(
            copy,
            root=root,
            thresholds=thresholds,
            gitleaks_config=None,
            runner=runner,
            label=f"the starting checkpoint ({commit[:12]})",
        )


def ids_by_scanner(report: Report, scanner: str) -> list[str]:
    """Return the ids of one scanner's findings, in id order."""
    return [report.id_of(f) for f in report.sorted() if f.scanner == scanner]


def findings_in(report: Report, path: str) -> list[Finding]:
    """Return the report's findings that name ``path``."""
    return [finding for finding in report.sorted() if finding.path == path]


__all__ = [
    "DATABASE_MARKER",
    "GITLEAKS_CONFIG",
    "ID_DIGITS",
    "ID_PREFIX",
    "PINS_PATH",
    "REPORTS_DIRECTORY",
    "SARIF_NAME",
    "SBOM_NAME",
    "SCANNERS",
    "SUPPLIED_GITLEAKS_CONFIG",
    "SUPPLIED_GITLEAKS_RULE_ID",
    "Finding",
    "Match",
    "Pin",
    "Pins",
    "Report",
    "ScanError",
    "TrivyDatabase",
    "cached_database",
    "copy_tree_for_scan",
    "ensure_trivy_database",
    "finding_id",
    "finding_ids",
    "findings_in",
    "id_order",
    "ids_by_scanner",
    "load_pins",
    "parse_gitleaks",
    "parse_semgrep",
    "parse_trivy",
    "pull_images",
    "run_docker",
    "sarif",
    "scan",
    "scan_baseline",
    "scan_seeded",
    "scan_working_tree",
    "tree_files",
    "write_reports",
]


def iter_findings(reports: Iterable[Report]) -> Iterable[tuple[Report, Finding]]:
    """Yield every (report, finding) pair, for callers that walk several scans."""
    for report in reports:
        for finding in report.sorted():
            yield report, finding
