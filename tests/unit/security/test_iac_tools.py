"""Coldline.

===================

File:              tests/unit/security/test_iac_tools.py
Component:         Unit tests — The infrastructure tooling
Purpose:           Prove the OpenTofu runner, the comparison, the scan reader, the triage rule,
                    the plan readers and the verify sequence behave as their modules state,
                    without Docker, OpenTofu, Trivy or LocalStack.
Interacts With:    tests/security/tofu.py, tests/security/infra_diff.py,
                    tests/security/tofu_scan.py, tests/security/iac_checks.py,
                    tests/security/iac_run.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.10
Concepts:          Tools tested on invented inputs, a command runner replaced by a stand-in
Tools:             Python 3.12, pytest

Every name, check id, prefix and count here is invented: the stack below is
``coldline-example-*``, the prefix ``coldline-probe``, and the check ids ``AVD-EXAMPLE-*``.
Of the supplied files, only the OpenTofu pin and ``infra/tofu/providers.tf`` (for its region)
are read. Nothing here reads ``infra/tofu/main.tf``, ``infra/tofu/.trivyignore`` or the
answer sheet.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from adapters.secrets import FIRST_VERSION_VALUE
from tests.security import iac_checks, iac_run, infra_diff, seeds, tofu, tofu_scan

TASK_ROOT = Path(__file__).resolve().parents[3]
PREFIX = "coldline-probe"
DIGEST = "sha256:" + "a" * 64
NAMES = infra_diff.StackNames(
    bucket="coldline-example-store",
    queue="coldline-example-work",
    dead_letter_queue="coldline-example-work-dlq",
    secret="coldline/example/key",
)
NETWORK = "coldline-example_coldline"
PIN_TEXT = (
    f'opentofu:\n  image: example.invalid/opentofu\n  version: "0.0.1"\n  digest: "{DIGEST}"\n'
)
SCANNER_ENTRIES = "".join(
    f'  {name}:\n    image: example.invalid/{name}\n    version: "0"\n    digest: "{DIGEST}"\n'
    for name in ("semgrep", "trivy", "gitleaks")
)
SCANNERS_TEXT = (
    f"scanners:\n{SCANNER_ENTRIES}"
    "trivy_db:\n"
    "  repository: example.invalid/trivy-db\n"
    f'  digest: "{DIGEST}"\n'
    "  cache: .tools/trivy-cache\n"
)


def _done(
    command: Sequence[str], stdout: str = "", code: int = 0
) -> subprocess.CompletedProcess[str]:
    """Return a finished command with the given output and exit code."""
    return subprocess.CompletedProcess(list(command), code, stdout, "")


def _stage_provider(root: Path) -> None:
    """Put one invented provider file in the plugin cache, as `poe tofu-setup` leaves one."""
    platform = root / tofu.PLUGIN_CACHE / "example.invalid/example/aws/0.0.1/linux_amd64"
    platform.mkdir(parents=True)
    (platform / "terraform-provider-aws_v0.0.1").write_text("example\n", encoding="utf-8")


def _name_expression() -> dict[str, Any]:
    return {"references": ["var.name_prefix"]}


def _plan(entries: Sequence[tuple[str, dict[str, Any], dict[str, Any]]]) -> dict[str, Any]:
    """Return a saved-plan document creating one managed resource per (address, values, exprs)."""
    changes: list[dict[str, Any]] = []
    planned: list[dict[str, Any]] = []
    configured: list[dict[str, Any]] = []
    for address, values, expressions in entries:
        resource_type = address.split(".")[0]
        common = {"address": address, "mode": "managed", "type": resource_type}
        changes.append({**common, "change": {"actions": ["create"]}})
        planned.append({**common, "values": values})
        configured.append(
            {**common, "address": iac_checks.config_address(address), "expressions": expressions}
        )
    return {
        "resource_changes": changes,
        "planned_values": {"root_module": {"resources": planned}},
        "configuration": {"root_module": {"resources": configured}},
    }


def _good_entries(
    prefix: str = PREFIX, redrive: dict[str, Any] | None = None
) -> list[tuple[str, dict[str, Any], dict[str, Any]]]:
    """Return the entries of a declaration that copies the example stack under ``prefix``."""
    by_reference = {"references": ["aws_sqs_queue.parked.arn", "aws_sqs_queue.parked"]}
    named = {"name": _name_expression()}
    return [
        (
            "aws_s3_bucket.store",
            {"bucket": f"{prefix}-example-store"},
            {"bucket": _name_expression()},
        ),
        (
            "aws_sqs_queue.work",
            {"name": f"{prefix}-example-work"},
            {**named, "redrive_policy": redrive or by_reference},
        ),
        ("aws_sqs_queue.parked", {"name": f"{prefix}-example-work-dlq"}, named),
        ("aws_secretsmanager_secret.key", {"name": f"{prefix}-example/key"}, named),
    ]


# --- tofu.py -----------------------------------------------------------------------------------


def test_the_pin_loads_and_an_unpinned_digest_is_refused(tmp_path: Path) -> None:
    """A real-shaped digest loads; the all-zero placeholder and a missing file do not."""
    (tmp_path / "infra").mkdir()
    (tmp_path / tofu.PIN_PATH).write_text(PIN_TEXT, encoding="utf-8")
    pin = tofu.load_pin(tmp_path)
    assert pin.reference == f"example.invalid/opentofu:0.0.1@{DIGEST}"

    (tmp_path / tofu.PIN_PATH).write_text(PIN_TEXT.replace(DIGEST, tofu.UNPINNED_DIGEST), "utf-8")
    with pytest.raises(tofu.TofuError, match="not pinned"):
        tofu.load_pin(tmp_path)
    with pytest.raises(tofu.TofuError, match="could not be read"):
        tofu.load_pin(tmp_path / "missing")


def test_the_shipped_pin_names_a_real_digest() -> None:
    """The OpenTofu image this repository runs is pinned by a digest, not the placeholder."""
    pin = tofu.load_pin(TASK_ROOT)

    assert pin.digest.startswith("sha256:") and pin.version


def test_the_docker_command_mounts_the_workspace_and_passes_the_prefix(tmp_path: Path) -> None:
    """OpenTofu runs in the pinned image, on the stack's network, in the workspace given."""
    pin = tofu.TofuPin("example.invalid/opentofu", "0.0.1", DIGEST)
    workspace = tofu.Workspace(tmp_path / "work", PREFIX, NETWORK)

    command = tofu.tofu_arguments(pin, workspace, tmp_path, ["plan", "-no-color"])

    assert command[:3] == ["docker", "run", "--rm"]
    assert command[command.index("--network") + 1] == NETWORK
    mounts = [command[index + 1] for index, part in enumerate(command) if part == "-v"]
    assert any(mount.endswith(":/work") for mount in mounts)
    assert any(mount.endswith(":/plugins") for mount in mounts)
    assert f"TF_VAR_name_prefix={PREFIX}" in command
    tail = command[command.index("--entrypoint") + 1 :]
    assert tail == ["tofu", pin.reference, "plan", "-no-color"]


def test_init_reads_the_lock_file_only_and_retries_a_failed_download(tmp_path: Path) -> None:
    """`tofu init` never rewrites the lock file, and a failed provider download is retried."""
    codes = iter([1, 1, 0])
    calls: list[list[str]] = []

    def runner(arguments: Sequence[str], capture: bool) -> subprocess.CompletedProcess[str]:
        calls.append(list(arguments))
        return _done(arguments, code=next(codes))

    pin = tofu.TofuPin("example.invalid/opentofu", "0.0.1", DIGEST)
    workspace = tofu.Workspace(tmp_path, PREFIX, None)
    command = tofu.Tofu(workspace, root=tmp_path, pin=pin, runner=runner)

    assert command.init().returncode == 0
    assert len(calls) == 3
    assert all("-lockfile=readonly" in call for call in calls)
    assert all("--network" not in call for call in calls)


def test_the_stack_prefix_is_refused(tmp_path: Path) -> None:
    """No workspace may be named from the stack's own `coldline`."""
    pin = tofu.TofuPin("example.invalid/opentofu", "0.0.1", DIGEST)
    with pytest.raises(tofu.TofuError, match="stack's own"):
        tofu.Tofu(tofu.Workspace(tmp_path, tofu.STACK_PREFIX, None), root=tmp_path, pin=pin)


def test_the_localstack_network_is_found_from_the_running_container() -> None:
    """The network ending in `_coldline` is chosen; a stopped stack is a clear error."""
    inspected = [{"NetworkSettings": {"Networks": {"bridge": {}, NETWORK: {}}}}]

    def running(arguments: Sequence[str], capture: bool) -> subprocess.CompletedProcess[str]:
        if list(arguments)[:2] == ["docker", "inspect"]:
            return _done(arguments, json.dumps(inspected))
        return _done(arguments, "example-container\n")

    assert tofu.localstack_network(TASK_ROOT, runner=running) == NETWORK

    def stopped(arguments: Sequence[str], capture: bool) -> subprocess.CompletedProcess[str]:
        return _done(arguments, "")

    with pytest.raises(tofu.TofuError, match="poe start"):
        tofu.localstack_network(TASK_ROOT, runner=stopped)


def test_planned_addresses_count_managed_creates_and_deletes() -> None:
    """Count creates and deletes per managed resource, and no data source or no-op."""
    plan = {
        "resource_changes": [
            {"address": "a.one", "mode": "managed", "change": {"actions": ["create"]}},
            {"address": "a.two", "mode": "managed", "change": {"actions": ["delete", "create"]}},
            {"address": "a.three", "mode": "managed", "change": {"actions": ["no-op"]}},
            {"address": "data.a.four", "mode": "data", "change": {"actions": ["read"]}},
        ]
    }

    assert tofu.planned_addresses(plan, "create") == ["a.one", "a.two"]
    assert tofu.planned_addresses(plan, "delete") == ["a.two"]
    assert tofu.planned_addresses({}, "create") == []


def test_the_supplied_provider_targets_us_east_1() -> None:
    """The region the provider names is the one a literal LocalStack ARN would carry."""
    text = (TASK_ROOT / tofu.TOFU_DIRECTORY / "providers.tf").read_text(encoding="utf-8")

    assert re.findall(r'(?m)^\s*region\s*=\s*"([^"]*)"', text) == ["us-east-1"]


def test_a_reference_with_a_tag_and_a_digest_is_inspected_by_its_digest() -> None:
    """Docker finds a pulled image by ``image@digest``; the tag beside the digest is dropped."""
    tagged = f"example.invalid:5000/opentofu:0.0.1@{DIGEST}"
    untagged = "example.invalid/opentofu:0.0.1"

    assert tofu.digest_reference(tagged) == f"example.invalid:5000/opentofu@{DIGEST}"
    assert tofu.digest_reference(untagged) == untagged


def test_a_missing_image_or_provider_names_poe_tofu_setup(tmp_path: Path) -> None:
    """Nothing is pulled: a missing image or an empty provider cache is reported, by name."""
    reference = f"example.invalid/opentofu:0.0.1@{DIGEST}"
    inspected: list[list[str]] = []

    def present(arguments: Sequence[str], capture: bool) -> subprocess.CompletedProcess[str]:
        inspected.append(list(arguments))
        return _done(arguments, "[]")

    def absent(arguments: Sequence[str], capture: bool) -> subprocess.CompletedProcess[str]:
        return _done(arguments, code=1)

    missing_provider = tofu.setup_problem(tmp_path, [reference], runner=present)
    assert missing_provider is not None and "poe tofu-setup" in missing_provider
    assert tofu.setup_problem(tmp_path, [reference], provider=False, runner=present) is None
    assert inspected[0] == ["docker", "image", "inspect", tofu.digest_reference(reference)]

    _stage_provider(tmp_path)
    assert tofu.setup_problem(tmp_path, [reference], runner=present) is None
    missing_image = tofu.setup_problem(tmp_path, [reference], runner=absent)
    assert missing_image is not None and "poe tofu-setup" in missing_image


def test_a_working_copy_takes_the_declarations_and_never_what_opentofu_writes(
    tmp_path: Path,
) -> None:
    """The copy holds the .tf files, the lock file and the ignore file, and no state or cache."""
    source = tmp_path / "source"
    (source / ".terraform/providers").mkdir(parents=True)
    for name in ("main.tf", "providers.tf", tofu.LOCK_FILE, tofu.IGNORE_FILE, tofu.STATE_FILE):
        (source / name).write_text("# example\n", encoding="utf-8")
    (source / "terraform.tfstate.backup").write_text("{}\n", encoding="utf-8")

    copied = tofu.copy_configuration(source, tmp_path / "copy")

    assert sorted(copied) == sorted(["main.tf", "providers.tf", tofu.LOCK_FILE, tofu.IGNORE_FILE])
    assert not (tmp_path / "copy/.terraform").exists()


# --- infra_diff.py -----------------------------------------------------------------------------


class FakeInventory:
    """LocalStack as a few dictionaries: buckets, queues with their attributes, and secrets."""

    def __init__(
        self, buckets: list[str], queues: dict[str, dict[str, Any]], secrets: list[str]
    ) -> None:
        """Hold the invented resources."""
        self.buckets = buckets
        self.queues = queues
        self.secrets = secrets

    def bucket_names(self) -> list[str]:
        """Return every bucket's name."""
        return sorted(self.buckets)

    def queue_names(self, prefix: str) -> list[str]:
        """Return the queues whose names start with the prefix."""
        return sorted(name for name in self.queues if name.startswith(prefix))

    def queue_attributes(self, name: str) -> dict[str, Any] | None:
        """Return one queue's attributes, or None."""
        return self.queues.get(name)

    def secret_names(self) -> list[str]:
        """Return every secret's name."""
        return sorted(self.secrets)


def _queue(visibility: str, receives: int | None, target: str | None) -> dict[str, Any]:
    attributes: dict[str, Any] = {"VisibilityTimeout": visibility}
    if receives is not None and target is not None:
        arn = f"arn:aws:sqs:us-east-1:000000000000:{target}"
        attributes["RedrivePolicy"] = json.dumps(
            {"deadLetterTargetArn": arn, "maxReceiveCount": receives}
        )
    return attributes


def _inventory(
    yours: dict[str, dict[str, Any]], buckets: list[str], secrets: list[str]
) -> FakeInventory:
    stack_queues = {
        NAMES.queue: _queue("40", 6, NAMES.dead_letter_queue),
        NAMES.dead_letter_queue: {"VisibilityTimeout": "40"},
    }
    return FakeInventory(
        [NAMES.bucket, *buckets], {**stack_queues, **yours}, [NAMES.secret, *secrets]
    )


def test_rest_of_strips_a_prefix_and_one_separator() -> None:
    """A hyphen or a slash after the prefix separates it; anything else does not."""
    assert infra_diff.rest_of("coldline-example-store", "coldline") == "example-store"
    assert infra_diff.rest_of("coldline/example/key", "coldline") == "example/key"
    assert infra_diff.rest_of("coldline-probe-example/key", PREFIX) == "example/key"
    assert infra_diff.rest_of("coldlinex-store", "coldline") is None
    assert infra_diff.rest_of("coldline", "coldline") is None


def test_a_matching_copy_has_no_difference_and_extra_settings_are_not_compared() -> None:
    """Each resource pairs by name; only the stack's settings are compared."""
    yours = {
        f"{PREFIX}-example-work": {
            **_queue("40", 6, f"{PREFIX}-example-work-dlq"),
            "SqsManagedSseEnabled": "true",
        },
        f"{PREFIX}-example-work-dlq": {"VisibilityTimeout": "99"},
    }
    inventory = _inventory(yours, [f"{PREFIX}-example-store"], [f"{PREFIX}-example/key"])

    comparison = infra_diff.compare(
        infra_diff.stack_resources(inventory, NAMES),
        infra_diff.your_resources(inventory, PREFIX),
        PREFIX,
    )

    assert comparison.count == 0
    assert comparison.unpaired_yours == ()
    assert comparison.lines()[-1] == "infra-diff: 0 difference(s)"


@pytest.mark.parametrize("separator", ["-", "/"])
def test_the_secret_pairs_with_either_separator_after_the_prefix(separator: str) -> None:
    """The stack's ``coldline/example/key`` pairs after the prefix with a hyphen or a slash."""
    secret = f"{PREFIX}{separator}example/key"
    yours = {
        f"{PREFIX}-example-work": _queue("40", 6, f"{PREFIX}-example-work-dlq"),
        f"{PREFIX}-example-work-dlq": {},
    }
    inventory = _inventory(yours, [f"{PREFIX}-example-store"], [secret])

    comparison = infra_diff.compare(
        infra_diff.stack_resources(inventory, NAMES),
        infra_diff.your_resources(inventory, PREFIX),
        PREFIX,
    )
    entries = _good_entries()
    address, _, expressions = entries[3]
    entries[3] = (address, {"name": secret}, expressions)
    plan = _plan(entries)
    expected = iac_checks.expected_resources(NAMES)

    assert comparison.count == 0 and comparison.unpaired_yours == ()
    assert iac_checks.naming_problems(plan, expected, PREFIX) == []
    assert iac_checks.shape_problems(plan, expected) == []


def test_each_differing_setting_and_each_missing_pair_is_one_difference() -> None:
    """A different timeout, receive count and target, and a missing secret: four differences."""
    yours = {
        f"{PREFIX}-example-work": _queue("10", 2, NAMES.dead_letter_queue),
        f"{PREFIX}-example-work-dlq": {},
    }
    inventory = _inventory(yours, [f"{PREFIX}-example-store", f"{PREFIX}-extra"], [])

    comparison = infra_diff.compare(
        infra_diff.stack_resources(inventory, NAMES),
        infra_diff.your_resources(inventory, PREFIX),
        PREFIX,
    )

    settings = sorted(difference.setting for difference in comparison.differences)
    assert settings == sorted(
        [infra_diff.VISIBILITY, infra_diff.MAX_RECEIVES, infra_diff.DEAD_LETTER, infra_diff.PAIR]
    )
    target = next(d for d in comparison.differences if d.setting == infra_diff.DEAD_LETTER)
    assert (target.stack, target.yours) == ("example-work-dlq", NAMES.dead_letter_queue)
    assert comparison.unpaired_yours == (f"{PREFIX}-extra",)
    assert comparison.lines()[-1] == f"infra-diff: {comparison.count} difference(s)"


def test_a_queue_without_a_redrive_policy_differs_on_both_redrive_settings() -> None:
    """No redrive policy leaves the receive count and the target unset: two differences."""
    yours = {f"{PREFIX}-example-work": _queue("40", None, None), f"{PREFIX}-example-work-dlq": {}}
    inventory = _inventory(yours, [f"{PREFIX}-example-store"], [f"{PREFIX}/example/key"])

    comparison = infra_diff.compare(
        infra_diff.stack_resources(inventory, NAMES),
        infra_diff.your_resources(inventory, PREFIX),
        PREFIX,
    )

    assert sorted(d.setting for d in comparison.differences) == sorted(
        [infra_diff.MAX_RECEIVES, infra_diff.DEAD_LETTER]
    )
    assert all(d.yours == infra_diff.NOT_SET for d in comparison.differences)


def test_a_missing_stack_resource_stops_the_comparison() -> None:
    """Without the stack's own resources there is nothing to compare against."""
    inventory = FakeInventory([], {}, [])

    with pytest.raises(infra_diff.DiffError, match="poe start"):
        infra_diff.stack_resources(inventory, NAMES)
    with pytest.raises(infra_diff.DiffError, match="not the stack's own"):
        infra_diff.check_prefix(tofu.STACK_PREFIX)


def test_the_stack_names_come_from_compose_and_the_settings_defaults(tmp_path: Path) -> None:
    """The bucket comes from compose.yaml; the queues from ApiSettings unless compose overrides."""
    (tmp_path / "compose.yaml").write_text(
        "x-coldline-environment:\n  COLDLINE_S3_BUCKET: coldline-example-store\n",
        encoding="utf-8",
    )

    names = infra_diff.stack_names(tmp_path)

    assert names.bucket == "coldline-example-store"
    assert names.queue.startswith("coldline-") and names.dead_letter_queue.startswith(names.queue)
    assert names.secret.startswith("coldline/")


# --- tofu_scan.py ------------------------------------------------------------------------------


def _trivy(*results: tuple[str, str, str]) -> str:
    """Return Trivy configuration-scan JSON with one result per (check id, status, resource)."""
    return json.dumps(
        {
            "Results": [
                {
                    "Target": "main.tf",
                    "Misconfigurations": [
                        {
                            "ID": check_id,
                            "AVDID": f"AVD-{check_id}",
                            "Status": status,
                            "Severity": "HIGH",
                            "Title": "Example check",
                            "Resolution": "Set the example setting",
                            "CauseMetadata": {"Resource": resource, "StartLine": 3},
                        }
                        for check_id, status, resource in results
                    ],
                }
            ]
        }
    )


def test_the_scan_reader_groups_failures_by_check_id_and_names_each_resource() -> None:
    """One check id can name several resources; passes are kept but not printed."""
    result = tofu_scan.parse_trivy_config(
        _trivy(
            ("EXAMPLE-0001", "FAIL", "aws_sqs_queue.work"),
            ("EXAMPLE-0001", "FAIL", "aws_sqs_queue.parked"),
            ("EXAMPLE-0002", "PASS", "aws_s3_bucket.store"),
        )
    )

    assert list(result.failing()) == ["EXAMPLE-0001"]
    assert len(result.reports("AVD-EXAMPLE-0001")) == 2
    assert result.reports("example-0002", tofu_scan.PASS)
    text = "\n".join(result.lines("ignore file example"))
    assert "aws_sqs_queue.work (main.tf:3)" in text and "aws_sqs_queue.parked" in text
    assert "EXAMPLE-0002" not in text


def test_ignore_entries_carry_the_comment_line_directly_above() -> None:
    """Blank lines and comments are not entries; a comment counts only on the line just above."""
    entries = tofu_scan.parse_ignore(
        "# example reason, and what would make it unsafe\n"
        "AVD-EXAMPLE-0001\n"
        "\n"
        "AVD-EXAMPLE-0002 exp:2030-01-01\n"
        "#\n"
        "AVD-EXAMPLE-0003\n"
    )

    assert [entry.check_id for entry in entries] == [
        "AVD-EXAMPLE-0001",
        "AVD-EXAMPLE-0002",
        "AVD-EXAMPLE-0003",
    ]
    assert [bool(entry.comment) for entry in entries] == [True, False, False]
    assert tofu_scan.normalize("avd-example-0001") == tofu_scan.normalize("EXAMPLE-0001")


def _trivy_ids(check_id: str, alias: str, status: str) -> str:
    """Return Trivy JSON with one result whose ``ID`` and ``AVDID`` are exactly as given."""
    item = {"ID": check_id, "AVDID": alias, "Status": status, "CauseMetadata": {"Resource": "r"}}
    return json.dumps({"Results": [{"Target": "main.tf", "Misconfigurations": [item]}]})


@pytest.mark.parametrize("printed", ["EXAMPLE-0001", "AVD-EXAMPLE-0001"])
def test_the_scan_output_names_a_check_in_either_form(printed: str) -> None:
    """Whichever form Trivy prints as the ``ID``, with no alias, both spellings find it."""
    result = tofu_scan.parse_trivy_config(_trivy_ids(printed, "", "FAIL"))

    assert len(result.reports("EXAMPLE-0001")) == 1
    assert len(result.reports("avd-example-0001")) == 1


@pytest.mark.parametrize("answer", ["EXAMPLE-0001", "AVD-EXAMPLE-0001"])
@pytest.mark.parametrize("printed", ["EXAMPLE-0001", "AVD-EXAMPLE-0001"])
def test_the_answer_matches_the_scan_in_either_form(answer: str, printed: str) -> None:
    """A fix recorded in one spelling agrees with a scan that prints the other."""
    fixed = tofu_scan.parse_trivy_config(_trivy_ids(printed, "", "PASS"))

    assert tofu_scan.triage_problems(answer, "fix", [], fixed, fixed) == []


@pytest.mark.parametrize("entry", ["EXAMPLE-0001", "AVD-EXAMPLE-0001"])
def test_the_ignore_file_matches_the_answer_in_either_form(entry: str) -> None:
    """An accepted entry in one spelling agrees with an answer in the other; Trivy reads both."""
    without = tofu_scan.parse_trivy_config(_trivy_ids("EXAMPLE-0001", "", "FAIL"))
    hidden = tofu_scan.parse_trivy_config(_trivy())
    text = f"# safe here because example\n{entry} exp:2030-01-01\n"
    answer = tofu_scan.alternative_form(entry)
    entries = tofu_scan.parse_ignore(text)

    assert tofu_scan.triage_problems(answer, "accept", entries, hidden, without) == []
    given = tofu_scan.trivy_ignore_text(text).splitlines()
    assert given[1:] == [f"{entry} exp:2030-01-01", f"{answer} exp:2030-01-01"]
    assert len(entries) == 1, "entries are counted from your file as written"


def test_a_fix_agrees_only_when_the_check_now_passes_and_nothing_is_ignored() -> None:
    """A fixed check id passes on what was declared, fails nowhere, and has no ignore entry."""
    fixed = tofu_scan.parse_trivy_config(_trivy(("EXAMPLE-0001", "PASS", "aws_sqs_queue.work")))
    failing = tofu_scan.parse_trivy_config(_trivy(("EXAMPLE-0001", "FAIL", "aws_sqs_queue.work")))
    entry = tofu_scan.parse_ignore("# reason\nAVD-EXAMPLE-0009\n")

    assert tofu_scan.triage_problems("AVD-EXAMPLE-0001", "fix", [], fixed, fixed) == []
    assert tofu_scan.triage_problems("AVD-EXAMPLE-0001", "fix", [], failing, failing)
    assert tofu_scan.triage_problems("AVD-EXAMPLE-0001", "fix", entry, fixed, fixed)
    unknown = tofu_scan.triage_problems("AVD-EXAMPLE-0404", "fix", [], fixed, fixed)
    assert unknown and "not a check" in unknown[0]


def test_an_accept_agrees_only_with_one_commented_entry_that_hides_a_real_finding() -> None:
    """The scan reports it without the ignore file, not with it, and the entry has a comment."""
    without = tofu_scan.parse_trivy_config(_trivy(("EXAMPLE-0001", "FAIL", "aws_sqs_queue.work")))
    hidden = tofu_scan.parse_trivy_config(_trivy())
    commented = tofu_scan.parse_ignore("# safe here because example\nAVD-EXAMPLE-0001\n")
    bare = tofu_scan.parse_ignore("AVD-EXAMPLE-0001\n")
    two = tofu_scan.parse_ignore("# one\nAVD-EXAMPLE-0001\n# two\nAVD-EXAMPLE-0002\n")

    assert tofu_scan.triage_problems("EXAMPLE-0001", "accept", commented, hidden, without) == []
    assert tofu_scan.triage_problems("EXAMPLE-0001", "accept", bare, hidden, without)
    assert tofu_scan.triage_problems("EXAMPLE-0001", "accept", two, hidden, without)
    assert tofu_scan.triage_problems("EXAMPLE-0001", "accept", commented, without, without)
    assert tofu_scan.triage_problems("EXAMPLE-0001", "accept", commented, hidden, hidden)
    assert tofu_scan.triage_problems("EXAMPLE-0001", "ignore", commented, hidden, without)


# --- iac_checks.py -----------------------------------------------------------------------------


def test_a_copy_of_the_example_stack_has_no_shape_naming_or_redrive_problem() -> None:
    """The plan creates the stack's types once each, named from the prefix, redrive by reference."""
    plan = _plan(_good_entries())
    expected = iac_checks.expected_resources(NAMES)

    assert iac_checks.shape_problems(plan, expected) == []
    assert iac_checks.naming_problems(plan, expected, PREFIX) == []
    assert iac_checks.redrive_problems(plan, NAMES, PREFIX) == []
    assert len(iac_checks.created(plan)) == len(expected)


def test_an_extra_resource_a_secret_version_or_a_module_is_a_shape_problem() -> None:
    """Any created type the stack lacks, a secret version, or a module call is reported."""
    expected = iac_checks.expected_resources(NAMES)
    extra = _plan([*_good_entries(), ("aws_secretsmanager_secret_version.value", {}, {})])
    missing = _plan(_good_entries()[:2])
    module = _plan(_good_entries())
    module["configuration"]["root_module"]["module_calls"] = {"example": {}}
    read = _plan(_good_entries())
    read["configuration"]["root_module"]["resources"].append(
        {
            "address": "data.aws_secretsmanager_secret_version.value",
            "mode": "data",
            "type": iac_checks.SECRET_VERSION_TYPE,
            "expressions": {"secret_id": {"constant_value": NAMES.secret}},
        }
    )

    assert any(
        iac_checks.SECRET_VERSION_TYPE in problem
        for problem in iac_checks.shape_problems(extra, expected)
    )
    assert iac_checks.shape_problems(missing, expected)
    assert any("module" in problem for problem in iac_checks.shape_problems(module, expected))
    assert iac_checks.created(read) == iac_checks.created(_plan(_good_entries()))
    assert any(
        iac_checks.SECRET_VERSION_TYPE in problem
        for problem in iac_checks.shape_problems(read, expected)
    ), "a secret version read as a data source puts the value in the state too"


def test_a_resource_taken_over_rather_than_created_is_a_shape_and_a_plan_block_problem() -> None:
    """An ``import`` adds a configured resource the plan doesn't create; ``removed`` forgets one."""
    expected = iac_checks.expected_resources(NAMES)
    imported = _plan(_good_entries())
    imported["configuration"]["root_module"]["resources"].append(
        {"address": "aws_s3_bucket.taken", "mode": "managed", "type": "aws_s3_bucket"}
    )
    imported["resource_changes"].append(
        {
            "address": "aws_s3_bucket.taken",
            "mode": "managed",
            "type": "aws_s3_bucket",
            "change": {"actions": ["no-op"], "importing": {"id": "example-store"}},
        }
    )
    forgotten = _plan(_good_entries())
    forgotten["resource_changes"].append(
        {
            "address": "aws_s3_bucket.gone",
            "mode": "managed",
            "type": "aws_s3_bucket",
            "change": {"actions": ["forget"]},
        }
    )

    assert iac_checks.created(imported) == iac_checks.created(_plan(_good_entries()))
    assert any(
        "the declarations hold 2" in problem
        for problem in iac_checks.shape_problems(imported, expected)
    )
    assert any("import" in problem for problem in iac_checks.plan_block_problems(imported))
    assert any("removed" in problem for problem in iac_checks.plan_block_problems(forgotten))


def test_a_name_under_another_prefix_is_a_naming_problem_and_a_local_value_is_not() -> None:
    """Only the planned name counts: built through a ``locals`` value, it still matches."""
    expected = iac_checks.expected_resources(NAMES)
    through_local = _good_entries()
    address, values, _ = through_local[0]
    through_local[0] = (address, values, {"bucket": {"references": ["local.store_name"]}})

    assert iac_checks.naming_problems(_plan(through_local), expected, PREFIX) == []
    elsewhere = iac_checks.naming_problems(_plan(_good_entries()), expected, "coldline-other")
    assert len(elsewhere) == len(expected)


def test_a_provisioner_or_another_provider_configuration_in_the_plan_is_reported() -> None:
    """The supplied ``aws`` configuration is the only one; a provisioner is never allowed."""
    plan = _plan(_good_entries())
    assert iac_checks.plan_block_problems(plan) == []

    plan["configuration"]["provider_config"] = {"aws": {}, "aws.elsewhere": {}}
    first = plan["configuration"]["root_module"]["resources"][0]
    first["provisioners"] = [{"type": "local-exec"}]
    problems = iac_checks.plan_block_problems(plan)
    assert len(problems) == 2
    assert any("aws.elsewhere" in problem for problem in problems)


def _tofu_files(root: Path, **files: str) -> Path:
    """Write the supplied files and the given ones under infra/tofu/ of ``root``."""
    directory = root / tofu.TOFU_DIRECTORY
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "providers.tf").write_text(
        'terraform {\n}\n\nprovider "aws" {\n  region = "example"\n}\n', encoding="utf-8"
    )
    (directory / "variables.tf").write_text('variable "name_prefix" {}\n', encoding="utf-8")
    for name, text in files.items():
        (directory / name.replace("_", ".")).write_text(text, encoding="utf-8")
    return directory


def test_a_block_the_declarations_may_not_hold_is_found_and_the_supplied_files_are_not(
    tmp_path: Path,
) -> None:
    """Settings, backends, providers, modules and commands are named by file and line."""
    _tofu_files(tmp_path, main_tf='# provider "aws" {} in a comment\nresource "a" "b" {}\n')
    assert iac_checks.forbidden_block_problems(tmp_path) == []

    _tofu_files(
        tmp_path,
        main_tf=(
            'terraform {\n  backend "http" {\n    address = "example"\n  }\n}\n'
            'provider "aws" {\n  alias = "elsewhere"\n}\n'
            'module "example" {\n  source = "./example"\n}\n'
            'resource "a" "b" {\n  provider = aws.elsewhere\n'
            '  provisioner "local-exec" {\n    command = "true"\n  }\n'
            "  connection {\n  }\n}\n"
            "cloud {\n}\n"
            'import {\n  to = aws_s3_bucket.b\n  id = "example"\n}\n'
            "removed {\n  from = aws_s3_bucket.c\n}\n"
        ),
    )
    found = iac_checks.forbidden_block_problems(tmp_path)
    blocks = [problem.split("`")[1] for problem in found]
    assert blocks == [
        "terraform",
        "backend",
        "provider",
        "module",
        "provisioner",
        "connection",
        "cloud",
        "import",
        "removed",
    ]
    assert found[0].startswith("infra/tofu/main.tf:1 ")


def test_a_forbidden_block_with_unquoted_labels_is_found(tmp_path: Path) -> None:
    """HCL accepts a label without quotes, so ``provider aws {`` is a block all the same."""
    _tofu_files(
        tmp_path,
        main_tf=(
            "provider aws {\n  alias = elsewhere\n}\n"
            "resource a b {\n  provider = aws.elsewhere\n"
            "  provisioner local-exec {\n    command = true\n  }\n}\n"
            "module example {\n}\n"
        ),
    )
    found = iac_checks.forbidden_block_problems(tmp_path)

    assert [problem.split("`")[1] for problem in found] == ["provider", "provisioner", "module"]


def test_an_inline_scanner_ignore_anywhere_in_the_declarations_is_found(tmp_path: Path) -> None:
    """A ``trivy:ignore`` or ``tfsec:ignore`` comment fails; text that only looks alike does not."""
    _tofu_files(tmp_path, main_tf='# the scan ignores nothing here\nresource "a" "b" {}\n')
    assert iac_checks.inline_ignore_problems(tmp_path) == []

    _tofu_files(
        tmp_path,
        main_tf='#trivy:ignore:AVD-EXAMPLE-0001\nresource "a" "b" {}\n',
        extra_tf='resource "a" "c" {} # TFSEC:IGNORE:example-rule\n',
    )
    problems = iac_checks.inline_ignore_problems(tmp_path)
    assert [problem.split(" ")[0] for problem in problems] == [
        "infra/tofu/extra.tf:1",
        "infra/tofu/main.tf:1",
    ]
    assert all(".trivyignore" in problem for problem in problems)


def test_a_redrive_target_typed_out_as_text_is_not_a_reference() -> None:
    """A constant ARN, or a reference to something else, is a redrive problem."""
    constant = _plan(_good_entries(redrive={"constant_value": '{"deadLetterTargetArn": "x"}'}))
    other = _plan(_good_entries(redrive={"references": ["var.name_prefix"]}))

    assert "refers to nothing" in iac_checks.redrive_problems(constant, NAMES, PREFIX)[0]
    assert "var.name_prefix" in iac_checks.redrive_problems(other, NAMES, PREFIX)[0]


def test_a_redrive_that_refers_to_the_target_and_anything_else_is_a_problem() -> None:
    """Only the dead-letter queue resource may be referred to; an indexed arn is that resource."""
    target = ["aws_sqs_queue.parked.arn", "aws_sqs_queue.parked"]
    beside = {
        "variable": [*target, "var.name_prefix"],
        "local": [*target, "local.dead_letter_arn"],
        "other resource": [*target, "aws_sqs_queue.work.url"],
    }
    indexed = {"references": ["aws_sqs_queue.parked[0].arn", "aws_sqs_queue.parked"]}

    for case, referred in beside.items():
        plan = _plan(_good_entries(redrive={"references": referred}))
        problems = iac_checks.redrive_problems(plan, NAMES, PREFIX)
        assert problems and referred[-1] in problems[0], case
        assert "aws_sqs_queue.parked.arn," not in problems[0], case
    assert iac_checks.redrive_problems(_plan(_good_entries(redrive=indexed)), NAMES, PREFIX) == []


def test_a_secret_version_or_a_secret_value_under_infra_tofu_is_found(tmp_path: Path) -> None:
    """The first version's value, a provider-format key and a version block or read are named."""
    directory = tmp_path / tofu.TOFU_DIRECTORY
    (directory / ".terraform").mkdir(parents=True)
    (directory / "main.tf").write_text("# clean declarations\n", encoding="utf-8")
    (directory / ".terraform/cache.txt").write_text(FIRST_VERSION_VALUE, encoding="utf-8")
    assert iac_checks.secret_problems(tmp_path) == []

    (directory / "notes.tf").write_text(f"# {FIRST_VERSION_VALUE}\n", encoding="utf-8")
    (directory / "keys.tf").write_text(f"# {seeds.FAKE_KEY}\n", encoding="utf-8")
    (directory / "value.tf").write_text(
        'resource "aws_secretsmanager_secret_version" "value" {}\n', encoding="utf-8"
    )
    (directory / "read.tf").write_text(
        'data "aws_secretsmanager_secret_version" "value" {}\n', encoding="utf-8"
    )
    (directory / "bare.tf").write_text(
        "resource aws_secretsmanager_secret_version value {}\n", encoding="utf-8"
    )

    problems = iac_checks.secret_problems(tmp_path)
    assert len(problems) == 5
    assert any(problem.startswith("infra/tofu/bare.tf ") for problem in problems)
    assert any(problem.startswith("infra/tofu/read.tf ") for problem in problems)
    assert not any(FIRST_VERSION_VALUE in problem for problem in problems), "values never printed"


# --- iac_run.py --------------------------------------------------------------------------------


class FakeDocker:
    """Answer the docker commands the verify sequence makes, from invented plans and scans."""

    def __init__(self, plan: dict[str, Any], *, apply_code: int = 0, running: bool = True) -> None:
        """Hold the plan every show returns, the apply exit code, and whether the stack runs."""
        self.plan = plan
        self.apply_code = apply_code
        self.running = running
        self.calls: list[list[str]] = []

    def __call__(self, arguments: Sequence[str], capture: bool) -> subprocess.CompletedProcess[str]:
        """Return what Docker, OpenTofu or Trivy would print for one command."""
        command = list(arguments)
        self.calls.append(command)
        if command[:2] == ["docker", "compose"]:
            return _done(command, "example-container\n" if self.running else "")
        if command[:2] == ["docker", "inspect"]:
            return _done(command, json.dumps([{"NetworkSettings": {"Networks": {NETWORK: {}}}}]))
        if command[:3] == ["docker", "image", "inspect"]:
            return _done(command, "[]")
        if "config" in command:
            return _done(command, _trivy(("EXAMPLE-0001", "PASS", "aws_sqs_queue.work")))
        tofu_arguments = command[command.index("--entrypoint") + 3 :]
        if tofu_arguments[0] == "show":
            return _done(command, json.dumps(self._show(tofu_arguments[-1])))
        if tofu_arguments[0] == "apply" and iac_run.ADD_PLAN in tofu_arguments:
            return _done(command, code=self.apply_code)
        return _done(command)

    def _show(self, plan_file: str) -> dict[str, Any]:
        if plan_file != iac_run.DESTROY_PLAN:
            return self.plan
        deletes = [
            {**change, "change": {"actions": ["delete"]}}
            for change in self.plan["resource_changes"]
        ]
        return {"resource_changes": deletes}

    def tofu_calls(self) -> list[list[str]]:
        """Return the OpenTofu commands made, without the docker part."""
        return [
            call[call.index("--entrypoint") + 3 :] for call in self.calls if "--entrypoint" in call
        ]


def _verify_root(tmp_path: Path) -> Path:
    """Stage a Task root with the two pin files and an OpenTofu project."""
    (tmp_path / "infra/tofu").mkdir(parents=True)
    (tmp_path / "security").mkdir()
    (tmp_path / tofu.PIN_PATH).write_text(PIN_TEXT, encoding="utf-8")
    (tmp_path / "security/scanners.yaml").write_text(SCANNERS_TEXT, encoding="utf-8")
    for name in ("main.tf", "providers.tf", "variables.tf", tofu.LOCK_FILE, tofu.IGNORE_FILE):
        (tmp_path / "infra/tofu" / name).write_text("# example\n", encoding="utf-8")
    _stage_provider(tmp_path)
    return tmp_path


def test_the_verify_run_stops_naming_poe_tofu_setup_when_the_provider_is_missing(
    tmp_path: Path,
) -> None:
    """Without the cached provider no OpenTofu step runs, and each step's reason names setup."""
    root = _verify_root(tmp_path)
    shutil.rmtree(root / tofu.PLUGIN_CACHE)
    docker = FakeDocker(_plan(_good_entries("coldline-verify-abcdef")))

    observed = iac_run.observe(root, prefix="coldline-verify-abcdef", runner=docker)

    assert docker.tofu_calls() == []
    assert observed.plan is None and observed.scan_ignored is None
    assert "poe tofu-setup" in observed.plan_error and "poe tofu-setup" in observed.scan_error
    assert "poe tofu-setup" in observed.summary()


def test_the_verify_run_uses_its_own_prefix_and_copy_and_observes_each_step(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Every step runs in the verify copy under the verify prefix, never in the sandbox."""
    root = _verify_root(tmp_path)
    plan = _plan(_good_entries("coldline-verify-abcdef"))
    docker = FakeDocker(plan)
    compared: list[str] = []

    def comparison(root: Path, prefix: str) -> infra_diff.Comparison:
        compared.append(prefix)
        return infra_diff.Comparison(prefix, (), (), ())

    monkeypatch.setattr(iac_run.infra_diff, "run", comparison)

    observed = iac_run.observe(root, prefix="coldline-verify-abcdef", runner=docker)

    created = len(iac_checks.created(plan))
    assert (observed.planned_adds, observed.destroy_count, observed.replanned_adds) == (
        created,
        created,
        created,
    )
    assert observed.comparison is not None and compared == ["coldline-verify-abcdef"]
    assert observed.state_after_destroy == []
    assert not (root / iac_run.VERIFY_DIRECTORY / iac_run.PREFIX_RECORD).exists()
    assert observed.scan_ignored is not None and observed.scan_unignored is not None
    prefixes = {part for call in docker.calls for part in call if part.startswith("TF_VAR_")}
    assert prefixes == {"TF_VAR_name_prefix=coldline-verify-abcdef"}
    mounts = {call[call.index("-v") + 1] for call in docker.calls if "--entrypoint" in call}
    assert all(str((root / iac_run.VERIFY_DIRECTORY).resolve()) in mount for mount in mounts)
    assert not (root / "infra/tofu" / tofu.STATE_FILE).exists()


def test_a_failed_apply_is_recorded_and_whatever_it_created_is_destroyed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The apply's failure is kept for the rows, and a destroy still runs before returning."""
    root = _verify_root(tmp_path)
    docker = FakeDocker(_plan(_good_entries("coldline-verify-abcdef")), apply_code=1)
    monkeypatch.setattr(iac_run.infra_diff, "run", lambda root, prefix: None)

    observed = iac_run.observe(root, prefix="coldline-verify-abcdef", runner=docker)

    assert observed.apply_attempted and not observed.applied
    assert observed.comparison is None and observed.destroy_count is None
    assert any(call[0] == "destroy" for call in docker.tofu_calls())
    assert "apply:" in observed.summary()


def test_a_plan_with_a_provisioner_or_a_type_the_stack_lacks_is_never_applied(
    tmp_path: Path,
) -> None:
    """The run plans, reads the plan, and stops before an apply that would act beyond the stack."""
    root = _verify_root(tmp_path)
    provisioned = _plan(_good_entries("coldline-verify-abcdef"))
    provisioned["configuration"]["root_module"]["resources"][0]["provisioners"] = [
        {"type": "local-exec"}
    ]
    elsewhere = _plan([*_good_entries("coldline-verify-abcdef"), ("aws_iam_role.r", {}, {})])

    for plan, reason in ((provisioned, "provisioner"), (elsewhere, "aws_iam_role")):
        docker = FakeDocker(plan)
        observed = iac_run.observe(root, prefix="coldline-verify-abcdef", runner=docker)

        assert observed.plan is not None and not observed.apply_attempted
        assert observed.apply_error.startswith("not applied: ") and reason in observed.apply_error
        assert not any(call[0] in ("apply", "destroy") for call in docker.tofu_calls())
        assert observed.scan_ignored is not None


def test_a_resource_named_outside_the_prefix_is_never_applied(tmp_path: Path) -> None:
    """A name without the run's prefix could be the stack's own resource, so nothing applies."""
    root = _verify_root(tmp_path)
    entries = _good_entries("coldline-verify-abcdef")
    address, values, extra = entries[0]
    renamed = {
        **values,
        **{key: "coldline-example-store" for key in values if key in ("bucket", "name")},
    }
    plan = _plan([(address, renamed, extra), *entries[1:]])
    docker = FakeDocker(plan)

    observed = iac_run.observe(root, prefix="coldline-verify-abcdef", runner=docker)

    assert not observed.apply_attempted
    assert "not from the prefix coldline-verify-abcdef" in observed.apply_error
    assert not any(call[0] in ("apply", "destroy") for call in docker.tofu_calls())


def test_a_stopped_stack_fails_each_step_instead_of_erroring(tmp_path: Path) -> None:
    """With no running localstack container, no OpenTofu step runs and the reason names it."""
    root = _verify_root(tmp_path)
    docker = FakeDocker(_plan(_good_entries("coldline-verify-abcdef")), running=False)

    observed = iac_run.observe(root, prefix="coldline-verify-abcdef", runner=docker)

    assert docker.tofu_calls() == []
    assert observed.plan is None and "poe start" in observed.plan_error
    assert observed.scan_ignored is not None and observed.scan_unignored is not None
    assert "poe start" in observed.summary()
