"""Coldline.

===================

File:              tests/contract/test_submission.py
Component:         Contract tests — Test Submission
Purpose:           Tests for the public answer and path checks for this Task's submission.
Interacts With:    Published interfaces and repository boundaries
Sprint/Task:       Sprint 4 — Project 4 / Task 4.10
Concepts:          Compatibility, ownership, export safety
Tools:             Python 3.12, pytest
"""

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.contract.submission_validation import (
    ALLOWED_PATHS,
    ANSWER_FIELDS,
    COUNT_FIELDS,
    LIMIT_OPTIONS,
    RECOMMENDATIONS,
    TRIAGE_DECISIONS,
    SubmissionError,
    _load_one_document,
    main,
    validate_changed_paths,
    validate_submission,
)

ROOT = Path(__file__).parents[2]
SCHEMA = ROOT / "docs/contracts/submission.schema.json"
TEMPLATE = ROOT / "tests/fixtures/submission-template.yaml"
PERMITTED = [
    "submission.yaml",
    "infra/tofu/main.tf",
    "infra/tofu/.trivyignore",
    "docs/student/iac-record.md",
]


def valid_answers(**overrides: Any) -> dict[str, object]:
    """Return a complete answer sheet in the published shape.

    Fictional format example: these values show the shape and state no result. The counts
    are invented, the check id names no Trivy check, every local-limit option is listed
    (which is the shape of a list, not a reading of any option), and the decision and the
    recommendation are their first allowed values; the tests below use all of them.
    """
    answers: dict[str, Any] = {
        "plan_add_count": 9,
        "diff_count_before": 3,
        "diff_count_after": 1,
        "triaged_finding": "AVD-EXAMPLE-0001",
        "triage_decision": TRIAGE_DECISIONS[0],
        "destroy_count": 9,
        "local_limits": list(LIMIT_OPTIONS),
        "recommendation": RECOMMENDATIONS[0],
    }
    answers.update(overrides)
    return {"answers": answers}


def _task_root(tmp_path: Path, submission_text: str) -> Path:
    """Stage a minimal Task root the public verifier can validate."""
    (tmp_path / "docs/contracts").mkdir(parents=True)
    (tmp_path / "submission.yaml").write_text(submission_text, encoding="utf-8")
    (tmp_path / "submission-sample.yaml").write_text(
        (ROOT / "submission-sample.yaml").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (tmp_path / "docs/contracts/submission.schema.json").write_text(
        SCHEMA.read_text(encoding="utf-8"), encoding="utf-8"
    )
    return tmp_path


def test_a_complete_sheet_is_well_formed(tmp_path: Path) -> None:
    """The public schema accepts a complete sheet without judging its correctness."""
    root = _task_root(tmp_path, yaml.safe_dump(valid_answers()))

    validate_submission(root / "submission.yaml", SCHEMA)


@pytest.mark.parametrize("decision", TRIAGE_DECISIONS)
def test_both_triage_decisions_are_well_formed(tmp_path: Path, decision: str) -> None:
    """A fix and an accept both pass the format check; the schema prefers neither."""
    root = _task_root(tmp_path, yaml.safe_dump(valid_answers(triage_decision=decision)))

    validate_submission(root / "submission.yaml", SCHEMA)


@pytest.mark.parametrize("recommendation", RECOMMENDATIONS)
def test_every_recommendation_is_well_formed(tmp_path: Path, recommendation: str) -> None:
    """Each allowed recommendation passes; it is the student's call, so only the value counts."""
    sheet = valid_answers(recommendation=recommendation)
    root = _task_root(tmp_path, yaml.safe_dump(sheet))

    validate_submission(root / "submission.yaml", SCHEMA)


@pytest.mark.parametrize("option", LIMIT_OPTIONS)
def test_any_single_listed_option_is_a_well_formed_list(tmp_path: Path, option: str) -> None:
    """A one-option list of any listed option passes the format check."""
    root = _task_root(tmp_path, yaml.safe_dump(valid_answers(local_limits=[option])))

    validate_submission(root / "submission.yaml", SCHEMA)


def test_zero_differences_before_are_well_formed(tmp_path: Path) -> None:
    """A first comparison that found nothing is recorded as 0, which the format accepts."""
    sheet = valid_answers(diff_count_before=0, diff_count_after=0)
    root = _task_root(tmp_path, yaml.safe_dump(sheet))

    validate_submission(root / "submission.yaml", SCHEMA)


def test_blank_template_fails_with_field_address(tmp_path: Path) -> None:
    """An untouched answer sheet must identify the first incomplete field."""
    root = _task_root(tmp_path, TEMPLATE.read_text(encoding="utf-8"))

    with pytest.raises(SubmissionError, match="answers.plan_add_count is incomplete"):
        validate_submission(root / "submission.yaml", SCHEMA)


@pytest.mark.parametrize(
    "overrides,message",
    [
        ({"plan_add_count": -1}, "plan_add_count"),
        ({"plan_add_count": "9"}, "plan_add_count"),
        ({"plan_add_count": 9.5}, "plan_add_count"),
        ({"diff_count_before": True}, "diff_count_before"),
        ({"diff_count_after": "none"}, "diff_count_after"),
        ({"destroy_count": [9]}, "destroy_count"),
        ({"triaged_finding": "AVD EXAMPLE 0001"}, "triaged_finding"),
        ({"triaged_finding": "0001"}, "triaged_finding"),
        ({"triage_decision": "ignore"}, "triage_decision"),
        ({"triage_decision": "Fix"}, "triage_decision"),
        ({"local_limits": ["state-locking"]}, "local_limits"),
        ({"local_limits": ["apply_destroy_rebuild", "apply_destroy_rebuild"]}, "local_limits"),
        ({"local_limits": "iam_access"}, "local_limits"),
        ({"recommendation": "yes"}, "recommendation"),
    ],
    ids=[
        "negative-count",
        "count-as-text",
        "fractional-count",
        "boolean-count",
        "word-count",
        "count-as-list",
        "check-id-with-spaces",
        "check-id-digits-only",
        "unlisted-decision",
        "capitalised-decision",
        "unlisted-limit",
        "repeated-limit",
        "limit-not-a-list",
        "unlisted-recommendation",
    ],
)
def test_values_outside_the_published_contract_are_rejected(
    tmp_path: Path, overrides: dict[str, Any], message: str
) -> None:
    """The public schema must name the field it rejected, and reject the right ones."""
    sheet = valid_answers()
    answers = sheet["answers"]
    assert isinstance(answers, dict)
    answers.update(overrides)
    root = _task_root(tmp_path, yaml.safe_dump(sheet))

    with pytest.raises(SubmissionError, match=message):
        validate_submission(root / "submission.yaml", SCHEMA)


@pytest.mark.parametrize("field", ANSWER_FIELDS)
def test_a_missing_or_blank_field_is_named(tmp_path: Path, field: str) -> None:
    """Each of the eight answers is required, and a blank one is named as incomplete."""
    answers = dict(valid_answers()["answers"])  # type: ignore[arg-type]
    del answers[field]
    root = _task_root(tmp_path, yaml.safe_dump({"answers": answers}))
    with pytest.raises(SubmissionError, match=field):
        validate_submission(root / "submission.yaml", SCHEMA)

    blank = dict(valid_answers()["answers"])  # type: ignore[arg-type]
    blank[field] = [] if field == "local_limits" else ""
    root = _task_root(tmp_path / "blank", yaml.safe_dump({"answers": blank}))
    with pytest.raises(SubmissionError, match=f"answers.{field} is incomplete"):
        validate_submission(root / "submission.yaml", SCHEMA)


@pytest.mark.parametrize(
    "field",
    ["verify_passed", "instructor_approved", "scan_output", "notes"],
)
def test_no_self_attestation_or_report_field_is_accepted(tmp_path: Path, field: str) -> None:
    """Reject a self-approval, a pass boolean, a pasted output, or a free-text field."""
    answers = valid_answers()
    mapping = answers["answers"]
    assert isinstance(mapping, dict)
    mapping[field] = True
    root = _task_root(tmp_path, yaml.safe_dump(answers))

    with pytest.raises(SubmissionError, match="Additional properties"):
        validate_submission(root / "submission.yaml", SCHEMA)


def test_missing_answers_mapping_is_rejected(tmp_path: Path) -> None:
    """The answers mapping is required, not merely tolerated."""
    root = _task_root(tmp_path, "task: 4.10\n")

    with pytest.raises(SubmissionError, match="answers must be one mapping"):
        validate_submission(root / "submission.yaml", SCHEMA)


def test_exact_sample_copy_is_rejected(tmp_path: Path) -> None:
    """The published sample must not be accepted as a student submission."""
    root = _task_root(tmp_path, (ROOT / "submission-sample.yaml").read_text(encoding="utf-8"))

    with pytest.raises(SubmissionError, match="fictional sample"):
        validate_submission(
            root / "submission.yaml",
            SCHEMA,
            sample_path=root / "submission-sample.yaml",
        )


def test_public_entrypoint_reports_an_incomplete_answer_sheet(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Catch a verifier entrypoint that skips the real submission contract."""
    root = _task_root(tmp_path, TEMPLATE.read_text(encoding="utf-8"))

    assert main(root, changed_paths=[], format_only=True) == 1
    assert "answers.plan_add_count is incomplete" in capsys.readouterr().err


def test_public_entrypoint_rejects_the_sample_and_accepts_a_complete_sheet(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`poe answers` applies the sample-copy check; a complete sheet of its own passes."""
    copied = _task_root(tmp_path / "copied", (ROOT / "submission-sample.yaml").read_text("utf-8"))
    assert main(copied, changed_paths=[], format_only=True) == 1
    assert "fictional sample" in capsys.readouterr().err

    own = _task_root(tmp_path / "own", yaml.safe_dump(valid_answers()))
    assert main(own, changed_paths=[], format_only=True) == 0
    assert main(own, changed_paths=list(PERMITTED)) == 0


def test_public_entrypoint_reports_a_protected_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A change to the supplied provider configuration is named, not silently accepted."""
    root = _task_root(tmp_path, yaml.safe_dump(valid_answers()))

    assert main(root, changed_paths=["infra/tofu/providers.tf"]) == 1
    assert "protected path changed: infra/tofu/providers.tf" in capsys.readouterr().err
    assert main(root, changed_paths=["infra/tofu/providers.tf"], format_only=True) == 0


def test_only_the_four_student_files_are_permitted() -> None:
    """The four student files pass; every supplied file is a protected path."""
    assert ALLOWED_PATHS == frozenset(PERMITTED)
    validate_changed_paths(list(PERMITTED))

    for protected in (
        "infra/tofu/providers.tf",
        "infra/tofu/variables.tf",
        "infra/tofu/.terraform.lock.hcl",
        "infra/tofu/sandbox.tf",
        "infra/tofu/terraform.tfstate",
        "infra/opentofu.yaml",
        "src/api/initialize.py",
        "src/adapters/queue/sqs.py",
        "src/adapters/object_store/s3.py",
        "src/api/config.py",
        "docs/fidelity/SecretProvider.md",
        "tests/security/infra_diff.py",
        "tests/security/tofu_scan.py",
        "tests/contract/test_iac_contract.py",
        "security/scanners.yaml",
        ".github/workflows/task.yml",
        ".gitignore",
        "compose.yaml",
        "pyproject.toml",
        "uv.lock",
        "README.md",
        "submission-sample.yaml",
    ):
        with pytest.raises(SubmissionError, match="protected path changed"):
            validate_changed_paths([protected])


@pytest.mark.parametrize(
    "unsafe_text",
    [
        "answers: {value: first, value: second}\n",
        "answers: &answer {value: fictional}\n",
        "answers: *missing\n",
        "answers: {<<: {value: fictional}}\n",
        "answers: {value: 2026-09-04}\n",
        "answers: {value: !custom fictional}\n",
        "answers: {1: fictional}\n",
    ],
    ids=["duplicate-key", "anchor", "alias", "merge-key", "date", "custom-tag", "non-string-key"],
)
def test_non_json_yaml_constructs_are_rejected(tmp_path: Path, unsafe_text: str) -> None:
    """Reject restricted syntax before schema validation can mask a parser defect."""
    submission = tmp_path / "submission.yaml"
    submission.write_text(unsafe_text, encoding="utf-8")

    with pytest.raises(SubmissionError, match="restricted YAML"):
        _load_one_document(submission)


def test_multiple_yaml_documents_are_rejected(tmp_path: Path) -> None:
    """A second document cannot supply or replace the answer mapping."""
    submission = tmp_path / "submission.yaml"
    submission.write_text("answers: {}\n---\nanswers: {}\n", encoding="utf-8")

    with pytest.raises(SubmissionError, match="exactly one YAML mapping"):
        _load_one_document(submission)


def test_a_sheet_that_is_not_utf_8_is_a_submission_error(tmp_path: Path) -> None:
    """A sheet saved in another encoding gets the public error, not a Python traceback."""
    submission = tmp_path / "submission.yaml"
    submission.write_bytes("answers: {recommendation: same_way}\n".encode("utf-16"))

    with pytest.raises(SubmissionError, match="restricted YAML"):
        _load_one_document(submission)


def test_the_schema_names_the_allowed_values_and_the_field_forms() -> None:
    """The schema's enums are the sheet's values, and the counts are whole numbers from 0."""
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    answers = schema["properties"]["answers"]
    properties = answers["properties"]

    assert tuple(answers["required"]) == ANSWER_FIELDS
    assert answers["additionalProperties"] is False
    assert tuple(properties["triage_decision"]["enum"]) == TRIAGE_DECISIONS
    assert tuple(properties["recommendation"]["enum"]) == RECOMMENDATIONS
    limits = properties["local_limits"]
    assert tuple(limits["items"]["enum"]) == LIMIT_OPTIONS
    assert limits["uniqueItems"] is True and limits["minItems"] == 1
    for field in COUNT_FIELDS:
        assert properties[field] == {
            "description": properties[field]["description"],
            "$ref": "#/$defs/count",
        }
    assert schema["$defs"]["count"]["type"] == "integer"
    assert schema["$defs"]["count"]["minimum"] == 0


def test_the_options_are_listed_in_alphabetical_order() -> None:
    """The validator and the schema list the options in the alphabetical order of their ids.

    The order of the options is the order of their ids, so it says nothing about which of
    them the local run can establish. The answer sheet is yours to edit, so it is not read.
    """
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    listed = schema["properties"]["answers"]["properties"]["local_limits"]["items"]["enum"]

    assert list(LIMIT_OPTIONS) == sorted(LIMIT_OPTIONS)
    assert listed == list(LIMIT_OPTIONS)


def test_the_template_fixture_is_a_blank_sheet_with_the_eight_fields() -> None:
    """The fixture is the blank shape: empty strings and one empty list."""
    document = yaml.safe_load(TEMPLATE.read_text(encoding="utf-8"))

    assert document == {
        "answers": {field: [] if field == "local_limits" else "" for field in ANSWER_FIELDS}
    }


def test_the_sample_is_well_formed_and_names_no_real_check() -> None:
    """The sample passes the schema, and its check id is the invented example id."""
    document = yaml.safe_load((ROOT / "submission-sample.yaml").read_text(encoding="utf-8"))
    answers = document["answers"]

    assert answers["triaged_finding"] == "AVD-EXAMPLE-0000"
    assert answers["triage_decision"] in TRIAGE_DECISIONS
    assert answers["recommendation"] in RECOMMENDATIONS
    assert set(answers["local_limits"]) <= set(LIMIT_OPTIONS)
