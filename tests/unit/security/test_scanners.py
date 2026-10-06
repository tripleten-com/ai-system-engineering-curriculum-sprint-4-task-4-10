"""Coldline.

===================

File:              tests/unit/security/test_scanners.py
Component:         Unit tests — The three pinned scanners
Purpose:           Prove the finding ids are content-derived, fixed-width and edit-stable, that a
                    collision is an error and never a widened id, that ids sort numerically, that
                    each scanner's JSON becomes findings on one scale, that the gate's verdict and
                    the reports follow the thresholds, that the database cache is named by the
                    pinned digest and never reused for another, that the scan tree is a copy of the
                    files Git would track, and that the Docker commands carry the pins, the
                    read-only mount, the offline flags and the configuration asked for, all
                    without a container.
Interacts With:    tests/security/scanners.py, security/scanners.yaml, tests/security/gate.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          Pinned tools, offline scans, content-derived ids
Tools:             Python 3.12, pytest

`run_docker` is replaced by a scripted runner that answers from synthetic scanner outputs
and writes the files a scanner would write; the finding names below are invented.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from tests.security import scanners
from tests.security.gate import Thresholds

TASK_ROOT = Path(__file__).resolve().parents[3]


def _semgrep_result(rule: str, path: str, line: int, severity: str, message: str) -> dict:
    """Return one Semgrep result in the JSON shape the scanner prints."""
    return {
        "check_id": rule,
        "path": path,
        "start": {"line": line},
        "extra": {"severity": severity, "message": message},
    }


def _gitleaks_result(line: int) -> dict:
    """Return one Gitleaks finding in the JSON shape the report holds (an invented path)."""
    return {
        "RuleID": "example-token",
        "File": "/scan/src/example/values.yaml",
        "StartLine": line,
        "Description": "Example token",
    }


def _trivy_result(
    identifier: str, package: str, installed: str, fixed: str, severity: str, title: str
) -> dict:
    """Return one Trivy vulnerability in the JSON shape the scanner prints."""
    return {
        "VulnerabilityID": identifier,
        "PkgName": package,
        "InstalledVersion": installed,
        "FixedVersion": fixed,
        "Severity": severity,
        "Title": title,
    }


REPORT_ONLY = Thresholds("none", "none", "none")
POLICY = Thresholds("any", "high", "high")
SEMGREP_JSON = json.dumps(
    {
        "results": [
            _semgrep_result("rules.alpha", "src/a.py", 12, "WARNING", "Alpha pattern\nmore"),
            _semgrep_result("rules.alpha", "src/a.py", 4, "WARNING", "Alpha pattern"),
            _semgrep_result("rules.beta", "src/b.py", 7, "ERROR", "Beta pattern"),
        ],
        "errors": [],
    }
)
GITLEAKS_JSON = json.dumps(
    [
        _gitleaks_result(20),
        _gitleaks_result(21),
    ]
)
TRIVY_JSON = json.dumps(
    {
        "Results": [
            {
                "Target": "uv.lock",
                "Vulnerabilities": [
                    _trivy_result("CVE-0000-0001", "examplepkg", "1.0", "1.1", "HIGH", "Example"),
                    _trivy_result("CVE-0000-0002", "otherpkg", "2.0", "", "LOW", "Unfixed"),
                ],
            }
        ]
    }
)


def _finding(scanner: str, rule: str, path: str, severity: str = "medium") -> scanners.Finding:
    return scanners.Finding(scanner, rule, path, severity, rule, (scanners.Match(1, "match"),))


def test_ids_are_derived_from_scanner_rule_and_path_and_stable_across_edits() -> None:
    """Two digits from the key's digest; one key gives one id whatever else is reported."""
    alone = scanners.finding_ids([_finding("semgrep", "rules.alpha", "src/a.py")])
    beside = scanners.finding_ids(
        [
            _finding("semgrep", "rules.alpha", "src/a.py"),
            _finding("gitleaks", "example-token", "f.yaml"),
        ]
    )
    key = "semgrep|rules.alpha|src/a.py"
    assert alone[key] == beside[key] == scanners.finding_id(key)
    assert alone[key].startswith("F-") and len(alone[key]) == 2 + scanners.ID_DIGITS
    moved = scanners.Finding(
        "semgrep", "rules.alpha", "src/a.py", "medium", "other title", (scanners.Match(99, "m"),)
    )
    assert scanners.finding_ids([moved])[key] == alone[key], "the line is not part of the id"
    assert (
        scanners.finding_ids([_finding("semgrep", "rules.alpha", "src/a.py", "high")])[key]
        == (alone[key])
    ), "the severity is not part of the id either"


def _colliding_pair() -> tuple[scanners.Finding, scanners.Finding]:
    """Return two invented findings whose keys share one two-digit id."""
    first = _finding("semgrep", "rule-0", "src/a.py")
    target = scanners.finding_id(first.key)
    for index in range(1, 10_000):
        candidate = _finding("semgrep", f"rule-{index}", "src/a.py")
        if scanners.finding_id(candidate.key) == target:
            return first, candidate
    raise AssertionError("no colliding key found")


def test_ids_keep_their_width_when_findings_are_added_or_removed() -> None:
    """A finding's id is the same in a report of one, of many, and after another is gone.

    Variable width would let a finding's id change when a colliding finding appears or is
    fixed, which would break the comparisons between the baseline, inventory, clean and
    seeded reports; the width is fixed instead.
    """
    many = [_finding("semgrep", f"rule-{index}", f"src/{index}.py") for index in range(5)]
    ids = scanners.finding_ids(many)
    if len(set(ids.values())) != len(ids):
        pytest.skip("the invented keys collide; the collision test covers that")
    for finding in many:
        assert scanners.finding_ids([finding])[finding.key] == ids[finding.key]
        fewer = [other for other in many if other is not finding]
        assert {key: ids[key] for key in scanners.finding_ids(fewer)} == scanners.finding_ids(fewer)
    assert all(len(value) == 2 + scanners.ID_DIGITS for value in ids.values())


def test_a_collision_is_an_error_naming_both_findings_and_never_a_widened_id() -> None:
    """Two keys with one id stop the scan with a message naming both; no id is ever widened."""
    first, second = _colliding_pair()
    assert scanners.finding_id(first.key) == scanners.finding_id(second.key)
    with pytest.raises(scanners.ScanError, match="share one 2-digit id") as excinfo:
        scanners.finding_ids([first, second])
    assert first.key in str(excinfo.value) and second.key in str(excinfo.value)
    assert "course" in str(excinfo.value)
    assert scanners.finding_ids([first])[first.key] == scanners.finding_id(first.key)


def test_ids_sort_numerically_in_the_report() -> None:
    """`F-03` precedes `F-55`, and the order is the ids' numeric order, not a text sort."""
    assert scanners.id_order("F-03") == 3 and scanners.id_order("F-55") == 55
    findings = [_finding("semgrep", f"rule-{index}", "src/a.py") for index in range(8)]
    try:
        ids = scanners.finding_ids(findings)
    except scanners.ScanError:
        pytest.skip("the invented keys collide; the collision test covers that")
    report = scanners.Report("t", REPORT_ONLY, tuple(findings), ids, {}, {})
    ordered = [report.id_of(finding) for finding in report.sorted()]
    assert ordered == sorted(ordered, key=scanners.id_order)
    assert [scanners.id_order(identifier) for identifier in ordered] == sorted(
        scanners.id_order(identifier) for identifier in ordered
    )


def test_semgrep_results_group_by_rule_and_file_and_map_severities() -> None:
    """One finding per (rule, file) with every line, WARNING as medium and ERROR as high."""
    findings = scanners.parse_semgrep(SEMGREP_JSON)
    by_rule = {finding.rule: finding for finding in findings}
    assert set(by_rule) == {"rules.alpha", "rules.beta"}
    alpha = by_rule["rules.alpha"]
    assert alpha.path == "src/a.py" and alpha.severity == "medium" and alpha.lines == (4, 12)
    assert alpha.title == "Alpha pattern"
    assert by_rule["rules.beta"].severity == "high"
    with pytest.raises(scanners.ScanError, match="no JSON"):
        scanners.parse_semgrep("not json")
    with pytest.raises(scanners.ScanError, match="reported an error"):
        scanners.parse_semgrep(
            json.dumps({"results": [], "errors": [{"level": "error", "message": "bad rule"}]})
        )


def test_gitleaks_findings_group_by_rule_and_file_as_secrets_with_relative_paths() -> None:
    """The `/scan/` mount prefix is stripped; two matches in one file are one finding."""
    [finding] = scanners.parse_gitleaks(GITLEAKS_JSON)
    assert finding.scanner == "gitleaks" and finding.severity == "secret"
    assert finding.path == "src/example/values.yaml" and finding.rule == "example-token"
    assert finding.lines == (20, 21) and finding.title == "Example token"
    assert scanners.parse_gitleaks("") == [] and scanners.parse_gitleaks("[]") == []
    with pytest.raises(scanners.ScanError):
        scanners.parse_gitleaks("{}")


def test_trivy_vulnerabilities_become_one_finding_per_package_and_cve() -> None:
    """The rule is the CVE and the package; unfixed findings are dropped only when asked."""
    findings = scanners.parse_trivy(TRIVY_JSON)
    assert [finding.rule for finding in findings] == [
        "CVE-0000-0001:examplepkg",
        "CVE-0000-0002:otherpkg",
    ]
    assert findings[0].severity == "high" and findings[0].path == "uv.lock"
    assert findings[0].matches[0].detail == "examplepkg@1.0, fixed in 1.1"
    assert findings[1].severity == "low" and "no fixed version" in findings[1].matches[0].detail
    fixed_only = scanners.parse_trivy(TRIVY_JSON, ignore_unfixed=True)
    assert [f.rule for f in fixed_only] == ["CVE-0000-0001:examplepkg"]


def _report(thresholds: Thresholds) -> scanners.Report:
    findings = (
        *scanners.parse_semgrep(SEMGREP_JSON),
        *scanners.parse_gitleaks(GITLEAKS_JSON),
        *scanners.parse_trivy(TRIVY_JSON),
    )
    return scanners.Report(
        "a probe tree",
        thresholds,
        findings,
        scanners.finding_ids(findings),
        {"semgrep": "1", "gitleaks": "2", "trivy": "3"},
        {"semgrep": SEMGREP_JSON, "gitleaks": GITLEAKS_JSON, "trivy": TRIVY_JSON},
        json.dumps({"bomFormat": "CycloneDX", "components": [{"name": "examplepkg"}]}),
    )


def test_the_verdict_marks_findings_at_or_above_their_thresholds() -> None:
    """Report-only passes everything; the policy's thresholds fail the secret, HIGH and ERROR."""
    report_only = _report(REPORT_ONLY)
    assert report_only.passed and report_only.failing == ()
    assert "gate: passed" in report_only.lines()[-1]

    policy = _report(POLICY)
    failing = {(f.scanner, f.rule) for f in policy.failing}
    assert failing == {
        ("gitleaks", "example-token"),
        ("trivy", "CVE-0000-0001:examplepkg"),
        ("semgrep", "rules.beta"),
    }
    lines = policy.lines()
    assert lines[0].startswith("security-scan: 5 finding(s) on a probe tree (thresholds: ")
    assert sum(line.startswith("  ! ") for line in lines) == 3
    assert "gate: failed (3 finding(s)" in lines[-1]
    document = policy.as_document()
    assert document["passed"] is False and len(document["failing"]) == 3
    assert policy.path_of(policy.id_of(policy.findings[0])) == "src/a.py"
    assert policy.finding("F-00000") is None


def test_the_sarif_report_has_one_run_per_scanner_with_ids_and_the_verdict(tmp_path: Path) -> None:
    """SARIF 2.1.0, three runs in scanner order, each result tagged with its id and its verdict."""
    report = _report(POLICY)
    sarif_path, sbom_path = scanners.write_reports(report, tmp_path / "reports")

    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert [run["tool"]["driver"]["name"] for run in sarif["runs"]] == list(scanners.SCANNERS)
    results = [result for run in sarif["runs"] for result in run["results"]]
    assert len(results) == 5
    assert sum(result["properties"]["coldline/failsGate"] for result in results) == 3
    assert all(result["properties"]["coldline/findingId"].startswith("F-") for result in results)
    semgrep_run = sarif["runs"][0]
    alpha = next(r for r in semgrep_run["results"] if r["ruleId"] == "rules.alpha")
    assert [loc["physicalLocation"]["region"]["startLine"] for loc in alpha["locations"]] == [4, 12]
    assert json.loads(sbom_path.read_text(encoding="utf-8"))["bomFormat"] == "CycloneDX"
    assert all("versionControlProvenance" not in run for run in sarif["runs"])

    without_sbom = scanners.Report("t", POLICY, (), {}, {}, {}, None)
    with pytest.raises(scanners.ScanError, match="without the software bill of materials"):
        scanners.write_reports(without_sbom, tmp_path / "none")


def test_the_scanned_commit_is_recorded_in_every_sarif_run_when_given(tmp_path: Path) -> None:
    """`--revision` lands in each run's version-control provenance and properties."""
    revision = "0123456789abcdef0123456789abcdef01234567"
    sarif_path, _ = scanners.write_reports(_report(POLICY), tmp_path / "r", revision=revision)
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    for run in sarif["runs"]:
        assert run["versionControlProvenance"] == [{"revisionId": revision}]
        assert run["properties"]["coldline/revision"] == revision
        assert run["properties"]["coldline/scanned"] == "a probe tree"


def test_the_pins_file_names_three_images_and_the_database_by_digest() -> None:
    """The shipped security/scanners.yaml is supplied material: three sha256 pins, one database."""
    pins = scanners.load_pins(TASK_ROOT)
    assert set(pins.scanners) == set(scanners.SCANNERS)
    for name, pin in pins.scanners.items():
        assert pin.digest.startswith("sha256:")
        assert pin.reference == f"{pin.image}:{pin.version}@{pin.digest}"
        assert pin.name == name
    assert pins.trivy_db.reference.startswith("ghcr.io/aquasecurity/trivy-db@sha256:")
    assert pins.trivy_db.cache == Path(".tools/trivy-cache")
    assert pins.trivy_db.ignore_unfixed is False


def test_a_pins_file_without_a_digest_is_refused(tmp_path: Path) -> None:
    """A tag without a digest is not a pin."""
    (tmp_path / "security").mkdir()
    (tmp_path / "security/scanners.yaml").write_text(
        "scanners:\n  semgrep: {image: a, version: '1', digest: latest}\n"
        "  trivy: {image: b, version: '1', digest: 'sha256:0'}\n"
        "  gitleaks: {image: c, version: '1', digest: 'sha256:0'}\n"
        "trivy_db: {repository: r, digest: 'sha256:0', cache: .tools/x}\n",
        encoding="utf-8",
    )
    with pytest.raises(scanners.ScanError, match="not pinned by a sha256 digest"):
        scanners.load_pins(tmp_path)


def test_copy_tree_for_scan_skips_the_ignored_directories_outside_a_repository(
    tmp_path: Path,
) -> None:
    """Without Git the walk copies everything but the caches, the tools and the reports."""
    source = tmp_path / "source"
    for relative in (
        "src/a.py",
        ".venv/lib/x.py",
        ".tools/trivy-cache/2c3e2bb23325/db/metadata.json",
        "reports/security/scan.sarif",
        "security/seed/provider-key.txt",
    ):
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x\n", encoding="utf-8")

    copied = scanners.copy_tree_for_scan(source, tmp_path / "copy")

    assert copied == ["security/seed/provider-key.txt", "src/a.py"]
    assert scanners.tree_files(source) == ["security/seed/provider-key.txt", "src/a.py"]
    assert (tmp_path / "copy/src/a.py").is_file() and not (tmp_path / "copy/.venv").exists()


class ScriptedDocker:
    """Answer `docker run` for each scanner from the synthetic outputs; record every command."""

    def __init__(self, root: Path, *, trivy_exit: int = 0) -> None:
        """Remember the root (for the cache) and the exit code Trivy should give."""
        self.root = root
        self.trivy_exit = trivy_exit
        self.commands: list[list[str]] = []

    def _mount(self, arguments: list[str], target: str) -> Path | None:
        for index, argument in enumerate(arguments):
            if argument == "-v" and arguments[index + 1].endswith(f":{target}"):
                return Path(arguments[index + 1][: -len(f":{target}")])
        return None

    def __call__(self, arguments: list[str]) -> subprocess.CompletedProcess[str]:
        """Script one command."""
        self.commands.append(list(arguments))
        joined = " ".join(arguments)
        if arguments[0] == "pull":
            return subprocess.CompletedProcess(arguments, 0, "", "")
        out = self._mount(arguments, "/out")
        if "--download-db-only" in joined:
            cache = self._mount(arguments, "/cache")
            assert cache is not None
            (cache / "db").mkdir(parents=True, exist_ok=True)
            (cache / "db" / "metadata.json").write_text("{}", encoding="utf-8")
            return subprocess.CompletedProcess(arguments, 0, "", "")
        if "semgrep" in joined and "scan" in arguments:
            return subprocess.CompletedProcess(arguments, 1, SEMGREP_JSON, "")
        if "gitleaks" in joined:
            assert out is not None
            (out / "gitleaks.json").write_text(GITLEAKS_JSON, encoding="utf-8")
            return subprocess.CompletedProcess(arguments, 0, "", "")
        if "cyclonedx" in joined:
            assert out is not None
            (out / scanners.SBOM_NAME).write_text(
                json.dumps({"bomFormat": "CycloneDX"}), encoding="utf-8"
            )
            return subprocess.CompletedProcess(arguments, 0, "", "")
        if "trivy" in joined:
            assert out is not None
            if self.trivy_exit == 0:
                (out / "trivy.json").write_text(TRIVY_JSON, encoding="utf-8")
            return subprocess.CompletedProcess(arguments, self.trivy_exit, "", "trivy failed")
        raise AssertionError(f"unexpected docker command {arguments}")


def _tree(tmp_path: Path) -> Path:
    """Stage a tree that is also its own root: the pins file, the rules, a configuration, a lock.

    The Trivy cache is then created under this temporary root, never under the checkout's.
    """
    tree = tmp_path / "tree"
    (tree / "security").mkdir(parents=True)
    (tree / "security/scanners.yaml").write_text(
        (TASK_ROOT / "security/scanners.yaml").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (tree / "security/semgrep-rules.yaml").write_text("rules: []\n", encoding="utf-8")
    (tree / ".gitleaks.toml").write_text(
        "[extend]\nuseDefault = true\n[[allowlists]]\npaths=['x']\n", encoding="utf-8"
    )
    (tree / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    return tree


def test_scan_runs_the_three_pinned_scanners_offline_over_a_read_only_mount(tmp_path: Path) -> None:
    """The commands carry the digest references, `--network none`, the `:ro` mount and the flags."""
    tree = _tree(tmp_path)
    docker = ScriptedDocker(tree)
    pins = scanners.load_pins(tree)

    report = scanners.scan(
        tree,
        root=tree,
        thresholds=POLICY,
        gitleaks_config=tree / ".gitleaks.toml",
        runner=docker,
        sbom=True,
    )

    assert len(report.findings) == 5 and report.sbom is not None
    assert report.versions == {name: pins.scanners[name].version for name in scanners.SCANNERS}
    runs = [command for command in docker.commands if command[0] == "run"]
    download, semgrep, gitleaks, trivy, sbom = runs
    assert pins.trivy_db.reference in download
    for command in (semgrep, gitleaks, trivy, sbom):
        assert "--network" in command and command[command.index("--network") + 1] == "none"
        assert any(argument.endswith(f"{scanners.SCAN_MOUNT}:ro") for argument in command)
    assert pins.scanners["semgrep"].reference in semgrep and "--metrics=off" in semgrep
    assert "--no-rewrite-rule-ids" in semgrep and "--disable-version-check" in semgrep
    assert "--disable-nosem" in semgrep, "an inline nosemgrep marker must not hide a finding"
    assert pins.scanners["gitleaks"].reference in gitleaks
    assert "dir" in gitleaks and "--redact" in gitleaks
    assert "--ignore-gitleaks-allow" in gitleaks, "an inline gitleaks:allow marker hides no finding"
    assert pins.scanners["trivy"].reference in trivy
    offline = ("--skip-db-update", "--skip-java-db-update", "--offline-scan", "--include-dev-deps")
    for flag in offline:
        assert flag in trivy and flag in sbom
    assert "--ignore-unfixed" not in trivy
    assert "cyclonedx" in sbom and "--scanners" not in sbom


def test_the_inventory_configuration_is_the_supplied_rules_without_an_allowlist(
    tmp_path: Path,
) -> None:
    """With no configuration given, Gitleaks runs the supplied text; with one, that file's text."""
    tree = _tree(tmp_path)
    docker = ScriptedDocker(tree)
    seen: list[str] = []

    original = docker.__call__

    def capture(arguments: list[str]) -> subprocess.CompletedProcess[str]:
        if "gitleaks" in " ".join(arguments):
            config = docker._mount(arguments, "/config:ro")
            assert config is not None
            seen.append((config / "gitleaks.toml").read_text(encoding="utf-8"))
        return original(arguments)

    scanners.scan(tree, root=tree, thresholds=POLICY, gitleaks_config=None, runner=capture)
    scanners.scan(
        tree, root=tree, thresholds=POLICY, gitleaks_config=tree / ".gitleaks.toml", runner=capture
    )

    assert seen[0] == scanners.SUPPLIED_GITLEAKS_CONFIG and "allowlists" not in seen[0]
    assert "useDefault = true" in seen[0] and scanners.SUPPLIED_GITLEAKS_RULE_ID in seen[0]
    assert "[[allowlists]]" in seen[1]


def test_a_scanner_that_fails_is_a_scan_error_with_its_output(tmp_path: Path) -> None:
    """A non-zero exit without a report stops the scan and quotes the tool."""
    tree = _tree(tmp_path)
    docker = ScriptedDocker(tree, trivy_exit=3)
    with pytest.raises(scanners.ScanError, match="Trivy exited 3: trivy failed"):
        scanners.scan(tree, root=tree, thresholds=POLICY, runner=docker)


def test_scan_seeded_applies_the_seed_to_a_copy_and_leaves_the_tree_alone(tmp_path: Path) -> None:
    """The seed file exists in the scanned copy, never in the source tree."""
    source = _tree(tmp_path)
    docker = ScriptedDocker(source)
    mounted: list[Path] = []

    def capture(arguments: list[str]) -> subprocess.CompletedProcess[str]:
        if "gitleaks" in " ".join(arguments):
            scan_root = docker._mount(arguments, f"{scanners.SCAN_MOUNT}:ro")
            assert scan_root is not None
            mounted.append(scan_root)
            assert (scan_root / "security/seed/provider-key.txt").is_file()
        return docker(arguments)

    report = scanners.scan_seeded("secret", source, POLICY, runner=capture)

    assert mounted and not (source / "security/seed").exists()
    assert report.label == "a copy with the secret seed applied"


def _pins_root(tmp_path: Path, name: str, digest: str | None = None) -> Path:
    """Stage a root holding the shipped pins file, with the database digest replaced when asked."""
    root = tmp_path / name
    (root / "security").mkdir(parents=True, exist_ok=True)
    pins_text = (TASK_ROOT / "security/scanners.yaml").read_text(encoding="utf-8")
    if digest is not None:
        shipped = scanners.load_pins(TASK_ROOT).trivy_db.digest
        pins_text = pins_text.replace(shipped, digest)
    (root / "security/scanners.yaml").write_text(pins_text, encoding="utf-8")
    return root


def test_ensure_trivy_database_downloads_once_into_a_digest_named_cache_with_a_marker(
    tmp_path: Path,
) -> None:
    """The cache is `.tools/trivy-cache/<digest prefix>/`, marked with the pinned reference."""
    root = _pins_root(tmp_path, "root")
    pins = scanners.load_pins(root)
    docker = ScriptedDocker(root)

    cache = scanners.ensure_trivy_database(root, runner=docker)

    prefix = pins.trivy_db.digest.removeprefix("sha256:")[:12]
    assert cache == root / ".tools/trivy-cache" / prefix
    assert cache == pins.trivy_db.cache_for(root)
    assert (cache / "db/metadata.json").is_file()
    marker = cache / scanners.DATABASE_MARKER
    assert marker.read_text(encoding="utf-8").strip() == pins.trivy_db.reference
    assert len(docker.commands) == 1
    mounted = docker._mount(docker.commands[0], "/cache")
    assert mounted is not None and Path(mounted).resolve() == cache.resolve()
    scanners.ensure_trivy_database(root, runner=docker)
    assert len(docker.commands) == 1, "a present, marked database is not downloaded again"
    assert scanners.cached_database(cache, pins.trivy_db)


def test_a_digest_change_with_an_existing_cache_downloads_the_new_database_beside_it(
    tmp_path: Path,
) -> None:
    """After a re-pin the old cache is not reused: the new digest names a new directory."""
    root = _pins_root(tmp_path, "root")
    docker = ScriptedDocker(root)
    old_cache = scanners.ensure_trivy_database(root, runner=docker)
    old_pins = scanners.load_pins(root)

    new_digest = "sha256:" + "f" * 64
    _pins_root(tmp_path, "root", new_digest)
    new_pins = scanners.load_pins(root)
    assert new_pins.trivy_db.digest == new_digest
    new_cache = scanners.ensure_trivy_database(root, runner=docker)

    assert new_cache != old_cache and new_cache.parent == old_cache.parent
    assert new_cache.name == "f" * 12
    assert len(docker.commands) == 2, "the new digest is downloaded"
    assert new_pins.trivy_db.reference in docker.commands[1]
    assert (new_cache / scanners.DATABASE_MARKER).read_text(encoding="utf-8").strip() == (
        new_pins.trivy_db.reference
    )
    assert (old_cache / "db/metadata.json").is_file(), "the old cache is left where it is"
    assert not scanners.cached_database(old_cache, new_pins.trivy_db)
    assert scanners.cached_database(old_cache, old_pins.trivy_db)


def test_a_cache_with_a_missing_or_mismatched_marker_is_no_cache(tmp_path: Path) -> None:
    """A database with no marker, or one marked for another digest, is downloaded again."""
    root = _pins_root(tmp_path, "root")
    pins = scanners.load_pins(root)
    cache = pins.trivy_db.cache_for(root)
    (cache / "db").mkdir(parents=True)
    (cache / "db/metadata.json").write_text("{}", encoding="utf-8")
    docker = ScriptedDocker(root)

    assert not scanners.cached_database(cache, pins.trivy_db), "no marker: no cache"
    assert scanners.ensure_trivy_database(root, runner=docker) == cache
    assert len(docker.commands) == 1, "downloaded despite the metadata file"
    assert scanners.cached_database(cache, pins.trivy_db)

    (cache / scanners.DATABASE_MARKER).write_text("ghcr.io/other@sha256:" + "0" * 64 + "\n")
    assert not scanners.cached_database(cache, pins.trivy_db), "another pin's marker: no cache"
    scanners.ensure_trivy_database(root, runner=docker)
    assert len(docker.commands) == 2, "downloaded again"
    assert (cache / scanners.DATABASE_MARKER).read_text(encoding="utf-8").strip() == (
        pins.trivy_db.reference
    )


def test_a_failed_database_download_names_the_repin_step(tmp_path: Path) -> None:
    """A failed download points at the gate policy and writes no marker."""
    root = _pins_root(tmp_path, "root")
    pins = scanners.load_pins(root)
    docker = ScriptedDocker(root)
    assert scanners.ensure_trivy_database(root, runner=docker) == pins.trivy_db.cache_for(root)

    failing_root = _pins_root(tmp_path, "failing")

    def refuse(arguments: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(arguments, 1, "", "manifest unknown")

    with pytest.raises(scanners.ScanError, match="re-pin step"):
        scanners.ensure_trivy_database(failing_root, runner=refuse)
    failing_cache = scanners.load_pins(failing_root).trivy_db.cache_for(failing_root)
    assert not (failing_cache / scanners.DATABASE_MARKER).exists()
