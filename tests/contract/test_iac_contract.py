"""Coldline.

===================

File:              tests/contract/test_iac_contract.py
Component:         Contract tests — Infrastructure as code against LocalStack
Purpose:           One assessed check per automatable Check-list row: the declarations, the
                    plan, the comparison, the triage, the destroy and the plan after it, and the
                    counts and triage on the answer sheet against what this run observed.
Interacts With:    The running stack's LocalStack, tests/security/iac_run.py,
                    tests/security/iac_checks.py, tests/security/infra_diff.py,
                    tests/security/tofu_scan.py, infra/tofu/, submission.yaml
Sprint/Task:       Sprint 4 — Project 4 / Task 4.10
Concepts:          A plan as a reviewable record, drift on the settings one side sets, a triage
                    that travels with the code, a rebuild that is repeatable
Tools:             Python 3.12, pytest, Docker, OpenTofu, Trivy

Assessed: a fresh starter declares nothing in ``infra/tofu/main.tf`` and leaves the sheet
blank, so every row fails until the Task's work is done. ``poe contract`` deselects them;
``poe iac-contract`` and ``poe verify`` run them, once the stack is up and before the inherited
Project 4 checks.

The rows share one run (``tests/security/iac_run.py``): OpenTofu plans, applies, compares,
destroys and plans again over a copy of ``infra/tofu/``, with a prefix and a state of its own,
so the run never touches your ``coldline-sandbox`` resources or your state, and the
configuration scan reads the copied declarations with your ignore file and without it. Each
row then reads what that run observed. Where a row reads the plan, it reads what OpenTofu
planned for this run's prefix, which is why every name must come from ``var.name_prefix``.
"""

from __future__ import annotations

from typing import Any

import pytest

from tests.contract.submission_validation import SubmissionError, _load_one_document
from tests.security import iac_checks, iac_run, infra_diff, tofu_scan
from tests.security.iac_run import TASK_ROOT

pytestmark = pytest.mark.assessed


@pytest.fixture(scope="module")
def observed() -> iac_run.Observation:
    """Run the plan, apply, compare, destroy, plan-again sequence and the scans, once."""
    return iac_run.observe(TASK_ROOT)


@pytest.fixture(scope="module")
def names() -> infra_diff.StackNames:
    """Return the names the startup code gives the stack's resources."""
    return infra_diff.stack_names(TASK_ROOT)


@pytest.fixture(scope="module")
def answers() -> dict[str, Any]:
    """Return the answer sheet's answers, or an empty mapping when it cannot be read."""
    try:
        document = _load_one_document(TASK_ROOT / "submission.yaml")
    except SubmissionError:
        return {}
    found = document.get("answers")
    return found if isinstance(found, dict) else {}


def _plan(observed: iac_run.Observation) -> dict[str, Any]:
    """Return the run's plan, or fail with why OpenTofu could not plan."""
    if observed.plan is None:
        pytest.fail(f"`poe verify` could not plan your declarations:\n{observed.summary()}")
    return observed.plan


def _count(answers: dict[str, Any], field: str) -> int | None:
    """Return one count from the sheet, or None when it is not a whole number."""
    value = answers.get(field)
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def test_main_tf_declares_the_bucket_the_two_queues_and_the_secret_and_no_other(
    observed: iac_run.Observation, names: infra_diff.StackNames
) -> None:
    """The plan creates the stack's bucket, queue, dead-letter queue and secret types, no more.

    The declarations also hold no ``terraform``, ``backend``, ``cloud``, ``provider``,
    ``module``, ``provisioner``, ``connection``, ``import`` or ``removed`` block: those change
    where the state goes, what OpenTofu talks to, what it runs, or which existing resources it
    takes over or lets go of.
    """
    blocks = iac_checks.forbidden_block_problems(TASK_ROOT)
    assert blocks == [], "infra/tofu/main.tf holds a block the declarations may not hold"
    plan = _plan(observed)
    problems = iac_checks.shape_problems(plan, iac_checks.expected_resources(names))
    problems.extend(iac_checks.plan_block_problems(plan))

    assert problems == [], "infra/tofu/main.tf declares other resources than the stack has"


def test_each_resource_is_named_from_the_prefix_and_its_stack_name(
    observed: iac_run.Observation, names: infra_diff.StackNames
) -> None:
    """Each declared resource is named from var.name_prefix and the stack name it copies."""
    plan = _plan(observed)
    expected = iac_checks.expected_resources(names)
    problems = iac_checks.naming_problems(plan, expected, observed.prefix)

    assert problems == [], "a resource is not named from var.name_prefix and its stack name"


def test_the_secret_is_declared_with_no_version_and_no_value_under_infra_tofu(
    observed: iac_run.Observation, names: infra_diff.StackNames
) -> None:
    """The secret is declared with no version, and no file under infra/tofu/ holds its value."""
    plan = _plan(observed)
    secret = iac_checks.expected_resources(names)[3]
    declared = iac_checks.match_resource(plan, secret, observed.prefix)
    problems = iac_checks.secret_problems(TASK_ROOT)
    if iac_checks.SECRET_VERSION_TYPE in {item.resource_type for item in iac_checks.created(plan)}:
        problems.append(f"the plan creates an {iac_checks.SECRET_VERSION_TYPE}")

    assert declared is not None, "infra/tofu/main.tf declares no secret named from the prefix"
    assert problems == [], "declare the secret only: no secret version, and no value in a file"


def test_the_redrive_policy_refers_to_the_dead_letter_queue_resource(
    observed: iac_run.Observation, names: infra_diff.StackNames
) -> None:
    """The queue's redrive policy names the dead-letter queue resource's arn, by reference."""
    plan = _plan(observed)
    problems = iac_checks.redrive_problems(plan, names, observed.prefix)

    assert problems == [], "the redrive policy must refer to the dead-letter queue resource"


def test_the_plan_completes_and_adds_what_main_tf_declares(
    observed: iac_run.Observation,
) -> None:
    """OpenTofu plans the declarations without errors and plans to add at least one resource."""
    _plan(observed)

    assert observed.planned_adds, f"the plan adds nothing:\n{observed.summary()}"


def test_infra_diff_reports_zero_differences_after_the_apply(
    observed: iac_run.Observation,
) -> None:
    """After this run's apply, the comparison with the stack finds no setting difference."""
    if observed.comparison is None:
        pytest.fail(f"the comparison did not run:\n{observed.summary()}")
    report = "\n".join(observed.comparison.lines())

    assert observed.comparison.count == 0, f"the comparison found differences:\n{report}"


def test_destroy_removes_every_declared_resource_and_a_new_plan_adds_them_all_again(
    observed: iac_run.Observation,
) -> None:
    """The destroy deletes what the apply created, the state is empty, a new plan adds it all."""
    summary = observed.summary()
    added = observed.planned_adds

    assert observed.destroy_count, f"the destroy did not complete:\n{summary}"
    assert observed.destroy_count == added, f"the destroy deleted another set:\n{summary}"
    assert observed.state_after_destroy == [], "the state still tracks a destroyed resource"
    assert observed.replanned_adds == added, f"the new plan does not add them all:\n{summary}"


def test_the_answers_record_the_counts_poe_verify_observed(
    observed: iac_run.Observation, answers: dict[str, Any]
) -> None:
    """The plan, difference-after and destroy counts on the sheet are the ones this run saw."""
    comparison = observed.comparison
    seen = {
        "plan_add_count": observed.planned_adds,
        "diff_count_after": None if comparison is None else comparison.count,
        "destroy_count": observed.destroy_count,
    }
    mismatched = [
        f"answers.{field}: this run observed {value}"
        for field, value in seen.items()
        if value is None or _count(answers, field) != value
    ]

    assert mismatched == [], f"the sheet disagrees with this run:\n{observed.summary()}"


def test_the_triage_agrees_with_the_scan_and_the_ignore_file(
    observed: iac_run.Observation, answers: dict[str, Any]
) -> None:
    """A fixed check id is gone from the scan; an accepted one is the commented, single entry.

    An inline ``trivy:ignore`` comment in the declarations is neither: it hides a finding from
    both scans without an entry in infra/tofu/.trivyignore.
    """
    if observed.scan_ignored is None or observed.scan_unignored is None:
        pytest.fail(f"the configuration scan did not run: {observed.scan_error}")
    check_id = answers.get("triaged_finding")
    decision = answers.get("triage_decision")
    if not isinstance(check_id, str) or not check_id.strip() or not isinstance(decision, str):
        pytest.fail("answers.triaged_finding and answers.triage_decision are not recorded")
    problems = tofu_scan.triage_problems(
        check_id,
        decision,
        observed.ignore_entries,
        observed.scan_ignored,
        observed.scan_unignored,
    )
    problems.extend(iac_checks.inline_ignore_problems(TASK_ROOT))

    assert problems == [], "the triage disagrees with the scan or infra/tofu/.trivyignore"
