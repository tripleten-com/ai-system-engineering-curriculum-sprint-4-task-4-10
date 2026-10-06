<!--
Coldline - Task 4.7
Supplied checkpoint: a completion/reference version of the Task 6 decision record, carried
into the Task 4.7 checkpoint as settled material. It is not your evidence: at the Project
Defense, cite your own decision record at Task 6's accepted commit. It is not
student-editable in this Task; the only file a Task 4.7 pull request may change is
submission.yaml. The Task 6 template's unused "no go" and "go" sections keep their markers.
-->
# Decision record: relying on the exception-resolution workflow

## Decision

Outcome: conditional_go

The evidence supports relying on the exception-resolution workflow for the laboratory's exceptions once two conditions are met. No no-go rule applies: no stage of the development attack records `failed` (N1), every register entry names a control built in this Project (N2), and every entry has a test and an evidence record (N3). Two conditional-go rules apply: the redactor stage records `limited` (C1, through R-03), and the secret control's evidence is the Task 5 run rather than a stage of the combined attack (C2, through R-05).

## Evidence

- R-01, C-01: attack-dev:token_check `held` (the expired token refused with 401, no record returned, no summary_read added).
- R-02, C-02: attack-dev:output_schema `held` (the manipulated answer ended NEEDS_REVIEW with the fixed message and the reason code unknown_property).
- R-03, C-04: attack-dev:redactor `limited` (the phone number and the email address were replaced; the contact name opening a sentence reached the worker log line and the model request, RL-05).
- R-04, C-03: attack-dev:audit_trail `held` (the four worker events in order, one summary read with subject and role, no credential, the trace ids of the requests that recorded them).
- R-05, C-05: the Task 5 pull request citation in the register (the replacement accepted without a restart and the previous version refused); not exercised by the combined attack.
- The control matrix's limits for C-01 to C-05, carried into each entry's residual risk.

## Conditions (conditional go)

### Condition 1

- Applies to: C1:attack-dev:redactor
- What must be true: `poe attack-dev` records `held` for the `redactor` stage against the development note A-01, because a contact name that opens a sentence no longer reaches the worker log line or the model request: the redactor is raised to a version that recognizes a name that follows no contact cue, or the worker stops logging and sending the note's free text (rule C1, through R-03; `privacy-lead` is informed as the owner of R-03).
- Owner: platform-lead
- Evidence: attack-dev:redactor in a fresh evidence/attack-dev.json, with the redactor's version in docs/security/redactor.md.

### Condition 2

- Applies to: C2:R-05
- What must be true: On this checkpoint, `poe secret-replace`, then `poe scenario` and `poe provider-auth-check`, show the new key version accepted without a restart, and `poe secret-check-old` reports the previous version refused (rule C2, through R-05, whose evidence is the Task 5 run and not a stage of the combined attack).
- Owner: platform-lead
- Evidence: tests/unit/adapters/test_provider_keys.py::test_every_authentication_reads_the_store_again and docs/fidelity/SecretProvider.md, with the four command outputs and their timestamps recorded in the Task 7 evidence index.

## What must change first (no go)

[fill in: for a no go, one entry per required change, in the shape below; remove this marker and add entries as needed]

### Change 1

- Applies to: [fill in: N1:attack-dev:<stage> for a stage that recorded failed, N2:R-nn for an entry naming a control not in this Project, or N3:R-nn for an entry without a test or an evidence record]
- What must be true: [fill in: what would have to be true of the system or its evidence before relying on the workflow]
- Owner: [fill in: the role id from docs/governance/owners.md that can decide it]
- Evidence: [fill in: the test as path::name, the attack-dev:<stage>, the file or the pull request citation that would show it changed]

## Why no residual risk blocks a go (go)

[fill in: for a go, entry by entry, why no residual risk in the register blocks relying on the workflow]

## Accepted risk

Register id: R-04
Owner: platform-lead
Why it is acceptable now: Both acceptance rules hold: TH-05's supplied impact is 3, below the customer level (A1), and the audit-trail stage of the current run is `held` (A2). What remains is bounded: the trail records every summary read that returns a stored outcome with its subject, role and trace id, so the laboratory's first question, who read what, is answered for every stored-outcome read served by the API; what it cannot show is a request that returned no stored outcome (an unknown id, an unfinished record, a refused token) or a read of the audit table itself by a process holding the shared database role, and no such reader exists in the stack as shipped.
What evidence would change the decision: a summary read that returned a stored outcome for which `poe audit-trail` shows no `summary_read` event, a read of the `audit_events` table from a role other than the API's, or a second database role added for audit reads, which would close the residual and move R-04 out of the accepted set.
