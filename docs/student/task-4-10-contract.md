# Task 4.10 — Infrastructure as code against LocalStack: contract

The stack creates its own bucket, job queue, dead-letter queue and provider secret when it
starts. This Task asks you to describe the same resources as code that can be planned,
reviewed, applied and destroyed: you declare your own copy of them in OpenTofu against
LocalStack, compare your copy with what the startup code created, triage one finding of a
configuration scan, destroy and rebuild the copy, and record what the local run can't
establish about a real AWS account. This Task is optional: it gates no other Task.

## What is assessed, and by whom

| Assessed | By |
|---|---|
| Your declarations, the plan, the comparison, the triage, and the destroy and the plan after it | Automated, in this repository (`poe verify`, through `poe iac-contract`) |
| `plan_add_count`, `diff_count_after` and `destroy_count` match what `poe verify` observes | Automated (`poe iac-contract`) |
| `triaged_finding` and `triage_decision` agree with the scan and `infra/tofu/.trivyignore` | Automated (`poe iac-contract`) |
| The answer sheet's format, and the pull request's file boundary | Automated (`poe answers`, `poe submission`) |
| The Project 4 controls still pass | Automated (`poe verify`: the running platform, the end-to-end workflow and the carried Task 4.2, 4.3 and 4.4 tests) |
| `local_limits`, `plan_add_count` and `destroy_count` | The protected answer check, which runs after you submit on the platform and reports its result there |
| `diff_count_before` and `recommendation` | Their format only: a whole number from 0, and one allowed value |
| `docs/student/iac-record.md` and the evidence in your pull request description | Nothing: they are your working record |

## What is supplied

| Supplied | Where | Note |
|---|---|---|
| The OpenTofu project | `infra/tofu/providers.tf`, `infra/tofu/variables.tf`, `infra/tofu/.terraform.lock.hcl` | The AWS provider pinned by version and checksums, pointed at LocalStack with its development credentials; the `name_prefix` variable |
| The OpenTofu image | `infra/opentofu.yaml` | OpenTofu runs in this container image, pinned by digest; nothing is installed on your computer |
| The Trivy image and its checks | `security/scanners.yaml` | The same pinned image the security gate runs; the scan uses the checks built into it, offline |
| The startup code | `src/api/initialize.py`, `src/adapters/object_store/s3.py`, `src/adapters/queue/sqs.py`, `src/adapters/secrets/` | What the stack creates, and the settings it sets |
| The names and settings it reads | `compose.yaml`, `src/api/config.py`, `docs/fidelity/SecretProvider.md` | The bucket name, the visibility timeout and the maximum receive count; the queue names; the secret name |
| The commands | `poe tofu-setup`, `poe tofu-plan`, `poe tofu-apply`, `poe tofu-destroy`, `poe infra-diff`, `poe tofu-scan` | In `pyproject.toml` and `tests/security/` |

## Commands

Start the stack first (`poe start`): the OpenTofu commands and the comparison reach LocalStack
through it. Run `poe tofu-setup` once before Step 1: until it has run, the OpenTofu and scan
commands and `poe verify` stop with a message naming it. Run every command from the repository root as
`./.tools/bin/uv run --frozen poe <task>`.

| Command | What it does |
|---|---|
| `poe tofu-plan` | Runs `tofu init` from the lock file, then `tofu plan` in `infra/tofu/` with the `coldline-sandbox` prefix. The summary line says how many resources it would add |
| `poe tofu-apply` | The same, then `tofu apply -auto-approve`: it prints the plan and carries it out |
| `poe tofu-destroy` | `tofu destroy -auto-approve`: it prints what it will destroy, destroys it, and ends with the number of resources destroyed |
| `poe infra-diff` | Compares the stack's resources with yours and prints every difference and their count; exit 0 with none, 1 with some, 2 when it cannot run |
| `poe tofu-scan` | Trivy's configuration scan of `infra/tofu/`, with `infra/tofu/.trivyignore` as its ignore file: each check id it reports, its severity, the resources it names and the setting it recommends |
| `poe tofu-setup` | Pulls the OpenTofu and Trivy images and the provider; required once before Step 1, needs no stack, and changes nothing when run again |
| `poe answers`, `poe submission` | The answer sheet's format; with `submission`, the permitted files too |
| `poe verify` | The public command: all of the checks below |

Your sandbox's OpenTofu state is `infra/tofu/terraform.tfstate`, and OpenTofu keeps its
provider in `infra/tofu/.terraform/`. Git ignores both, so they never enter your pull request.
If you delete the state while resources still exist, OpenTofu forgets them: `poe tofu-apply`
then tries to create resources that already exist and fails. `poe reset` and `poe start`
empty LocalStack, after which a state that still lists resources describes nothing; delete
the state then, or run `poe tofu-destroy` before you reset.

## How `poe infra-diff` pairs and compares

- **The stack's resources** are the ones the startup code creates, named as it names them:
  the bucket from `compose.yaml`, the two queues from `src/api/config.py`, and the secret from
  `docs/fidelity/SecretProvider.md`.
- **Pairing.** A stack name is `coldline`, one separator (`-` or `/`) and the rest. Yours is
  the prefix, one separator and the same rest, for the same kind of resource. A stack
  resource with no pair is one difference. A resource of yours with no stack pair is listed
  and not counted.
- **The secret's name.** The stack's secret is `coldline/worker/model-provider-key`, so its
  sandbox copy is `coldline-sandbox-worker/model-provider-key`;
  `coldline-sandbox/worker/model-provider-key` pairs as well. The naming row accepts either
  separator after the prefix in the same way.
- **What is compared** is each setting the startup code sets on the stack's resource,
  against the same setting on yours, read from LocalStack as both are now. A setting the
  startup code doesn't set is never compared, so a stricter setting of yours isn't a
  difference. Where a setting names another resource, it is compared by that resource's name
  after its owner's prefix, so the stack's queue and yours each point at their own copy.
- **Never compared**: a secret's value, and anything about deleting a secret
  (`recovery_window_in_days`).

## How a triage is checked

`poe verify` scans the declarations twice: with your `infra/tofu/.trivyignore`, and with an
empty ignore file. A check id may be written with or without Trivy's `AVD-` prefix.

- **`fix`**: `infra/tofu/.trivyignore` has no entry, the scan reports the check id on no
  resource, and the scan shows it passing on at least one resource you declared. Choose a
  check id the scan reported before your change: the check sees only the current
  declarations, so it cannot tell a fixed finding from one that never failed.
- **`accept`**: `infra/tofu/.trivyignore` has exactly one entry, for that check id, with a
  comment line directly above it; the scan without the ignore file reports the check id, and
  the scan with it does not. The entry applies to every resource the check names, so the
  comment's reason has to hold for all of them.
- An inline `trivy:ignore` (or `tfsec:ignore`) comment in your declarations is never a fix or
  an accept: it hides the finding from both scans, so the triage row fails while one is
  there. Accept only through `infra/tofu/.trivyignore`.

## Check-list rows and the checks that read them

| Check-list row | Check |
|---|---|
| `infra/tofu/main.tf` declares the bucket, the queue, the dead-letter queue, and the secret, each named from `var.name_prefix` and the matching stack name, and no other resource | `test_main_tf_declares_the_bucket_the_two_queues_and_the_secret_and_no_other` (which also fails on any `terraform`, `backend`, `cloud`, `provider`, `module`, `provisioner`, `connection`, `import` or `removed` block in your declarations: `providers.tf` and `variables.tf` supply everything OpenTofu needs, and every resource is created, never taken over) and `test_each_resource_is_named_from_the_prefix_and_its_stack_name` in `tests/contract/test_iac_contract.py` |
| `infra/tofu/main.tf` declares no `aws_secretsmanager_secret_version` (as a resource or a data source: either puts the value in the state), and the provider secret's value appears in no file under `infra/tofu/` | `test_the_secret_is_declared_with_no_version_and_no_value_under_infra_tofu` |
| The queue's redrive policy refers to the dead-letter queue resource | `test_the_redrive_policy_refers_to_the_dead_letter_queue_resource`. The expression refers to the dead-letter queue resource's `arn` and to nothing else (no variable or `locals` value) |
| `poe tofu-plan` completes without errors | `test_the_plan_completes_and_adds_what_main_tf_declares` |
| After your last apply, `poe infra-diff` reports zero setting differences from the stack's resources | `test_infra_diff_reports_zero_differences_after_the_apply` |
| One scan check id is fixed, or accepted with a single entry and a comment above it in `infra/tofu/.trivyignore` | `test_the_triage_agrees_with_the_scan_and_the_ignore_file` |
| `poe tofu-destroy` removes every declared resource, and a following plan adds them all again | `test_destroy_removes_every_declared_resource_and_a_new_plan_adds_them_all_again` |
| `answers.plan_add_count`, `answers.diff_count_after`, and `answers.destroy_count` match what `poe verify` observes when it plans, compares, and destroys | `test_the_answers_record_the_counts_poe_verify_observed` |
| `answers.triaged_finding` and `answers.triage_decision` agree with the scan and `infra/tofu/.trivyignore` | `test_the_triage_agrees_with_the_scan_and_the_ignore_file` |
| `answers.diff_count_before` uses the allowed format | `poe answers` (`tests/contract/submission_validation.py --format-only`) |
| `answers.recommendation` uses an allowed value | `poe answers` |
| `answers.local_limits` uses the options in `submission.yaml` | `poe answers` |
| Your local limits pass the protected answer check | The protected answer check, after you submit on the platform |
| The Project 4 controls still pass their checks | `poe smoke`, `poe e2e-tests` and `poe student-tests` inside `poe verify` |
| The pull request modifies only `infra/tofu/main.tf`, `infra/tofu/.trivyignore`, `docs/student/iac-record.md`, and `submission.yaml` | `poe submission` inside `poe verify`, and `test_submission_change_stays_within_the_permitted_diff` in `tests/contract/test_authoring_contract.py` |

## What the checks verify

| Check | What it looks at |
|---|---|
| `tests/contract/test_iac_contract.py` (`poe iac-contract`) | One run of OpenTofu over a copy of `infra/tofu/` in `.tools/tofu-verify/`, with a `coldline-verify-` prefix and six random hex digits, new each run, and a state of its own, so it never touches your sandbox: `tofu init`, a saved plan read for what it creates and how each resource is named and referenced, that plan applied, the comparison above with this run's prefix, a saved destroy plan read for what it deletes and then applied, the state listed (it must be empty), and a new plan read for what it would create again. Whatever happens, what the run created is destroyed before it ends. Then the two scans. Each row reads what that run observed |
| `tests/contract/submission_validation.py` (`poe answers`, `poe submission`) | `submission.yaml` is one plain YAML mapping (no duplicate keys, aliases, anchors, merge keys or non-JSON tags) whose eight answers have their stated forms, and is not a copy of `submission-sample.yaml`. With `poe submission`, the diff from the merge base with `main` touches only the four permitted files |
| `tests/security/integrity.py` (`poe integrity-record`, `poe integrity-check`) | SHA-256 digests of the answer sheet, your declarations, your ignore file, your notes and every trusted file the checks rely on, recorded outside the repository when `poe verify` starts and compared when it ends |
| `poe smoke`, `poe e2e-tests`, `poe student-tests` inside `poe verify` | The Project 4 platform as supplied: the running stack, the end-to-end workflow, and the carried Task 4.2, 4.3 and 4.4 tests |

The hosted `security-gate` job also runs the settled Task 5 gate on your pull request; your
declarations and your ignore file go through it like every other file.

## Student-editable paths

- `infra/tofu/main.tf`
- `infra/tofu/.trivyignore`
- `docs/student/iac-record.md`
- `submission.yaml`

That is the whole list. The provider configuration, the variables, the lock file, the
OpenTofu and scan commands, the comparison, the startup code, `compose.yaml`, the supplied
tests and the workflows stay as supplied. Declare everything in `infra/tofu/main.tf`: a second
`.tf` file is a change outside the list. Before you push, run `git status` and
`git diff --stat`: if anything besides the four files changed, the public check reports the
boundary violation rather than your work.
