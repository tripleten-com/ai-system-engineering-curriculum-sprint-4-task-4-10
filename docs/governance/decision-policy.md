<!--
Coldline - Task 4.6
Supplied material: how the technical decision follows from the completed risk register and
the development attack evidence, which residual risks may be accepted, and what a condition
must contain. Not student-editable. The rule ids (N1 to N3, C1 and C2, G, A1 and A2) are
what the decision record cites; keep them if this file is revised.
-->
# Decision policy

Dana asked for one of three answers: whether the evidence supports relying on the
exception-resolution workflow for the laboratory's shipments. This policy says which answer
the evidence supports. It reads three supplied things and nothing else: the risk register's
entries, the limits the control matrix states for each control
(`docs/security/control-matrix.md`), and the stage outcomes `poe attack-dev` records in
`evidence/attack-dev.json`. Two people applying it to the same register and the same evidence
reach the same outcome.

## The three outcomes

| Value in `submission.yaml` | Meaning |
|---|---|
| `go` | The evidence supports relying on the workflow as it stands. No residual risk in the register blocks it, and the decision record says why. |
| `conditional_go` | The evidence supports relying on the workflow once named conditions are met. Each condition is specific enough to be checked later. |
| `no_go` | The evidence does not support relying on the workflow. The decision record says what would have to change first. |

## Stage outcomes

`poe attack-dev` records one outcome per stage, from what the control did with the attack's
input, under the key `outcome`:

| Outcome | Meaning |
|---|---|
| `held` | The control did what the control matrix says on every input the attack sent it. |
| `limited` | The control did what it does on the inputs it recognizes, and a documented limit of the control (the control matrix's limits section, or the redactor's limitations table in `docs/security/redactor.md`) let part of the attack's input through. |
| `failed` | The control did not do what the control matrix says on an input it is meant to act on. |

The combined attack exercises four controls: the token check on the summary read (C-01,
stage `token_check`), the output validation (C-02, stage `output_schema`), the redactor
(C-04, stage `redactor`) and the audit sink (C-03, stage `audit_trail`). The secret control
(C-05) and the security gate (C-06) have no stage: a register entry for either cites the Task
where you showed it.

## The rules

Apply the groups in order. The first group with a rule that applies gives the outcome.

### No-go

- **N1.** A stage in `evidence/attack-dev.json` records the outcome `failed`.
- **N2.** A register entry names a control the control matrix lists as "Not in this
  Project" in its last column.
- **N3.** A register entry has no test or no evidence record.

### Conditional go

When no no-go rule applies:

- **C1.** A stage in `evidence/attack-dev.json` records the outcome `limited`.
- **C2.** A register entry's evidence is a Task pull request citation rather than an
  `attack-dev` stage: the control was shown in an earlier Task's run, and the current run
  did not exercise it.

### Go

- **G.** No rule above applies.

A stage result that is not what its control is meant to do is evidence, not a broken run: the
outcome it records is what the rules read.

## What a condition must contain

For a conditional go, the decision record states one condition per rule that applied (one for
each `limited` stage, one for each entry whose evidence is from an earlier Task's run). Each
condition is one `### <heading>` entry under the "Conditions (conditional go)" section, with
four labelled lines:

- **Applies to**: the rule that applied and what it applied to, as `C1:attack-dev:<stage>`
  for a stage whose outcome is `limited`, or `C2:<register id>` (`C2:R-nn`) for an entry
  whose evidence is an earlier Task's pull request. The public check derives this set from
  `evidence/attack-dev.json` and your register exactly as C1 and C2 read them, and requires
  one complete entry per identifier: a rule that applied with no condition, a rule with two,
  and a condition for a rule that did not apply are each named;
- **What must be true**, as an observable statement about the system or its evidence, not an
  intention ("improve monitoring" is not a condition; "the redactor's version is raised to one
  that recognizes a contact name opening a sentence, and `poe attack-dev` records `held` for
  the redactor stage" is);
- **Owner**: the role id from `docs/governance/owners.md` that can decide it;
- **Evidence**: what would show it is met, as a citation someone checks later: a test as
  `<path>::<test name>`, a stage as `attack-dev:<stage>`, a file by its path, or a pull request
  in the register's documented form. The public check requires the owner to be a role id and
  the citation to resolve; whether the condition is sound is your instructor's question.

For a no-go, the decision record states what would have to change first, as entries of the
same shape under "What must change first (no go)", each applying to the no-go rule that
applied: `N1:attack-dev:<stage>` for a stage whose outcome is `failed`, `N2:<register id>` for
an entry naming a control the matrix lists as not in this Project, `N3:<register id>` for an
entry without a test or an evidence record. The public check reads the label's shape; which
no-go rule applied is your instructor's question. For a go, the record states why no residual
risk in the register blocks relying on the workflow, entry by entry, in prose.

## Residual risks you may accept

Whatever the outcome, exactly one residual risk is accepted for now and recorded in
`answers.accepted_risk`; the decision record says why it is acceptable, who owns it (the owner
role the register records for that entry) and what evidence would change the decision. A
register entry may be the accepted risk when both hold:

- **A1.** The supplied impact of its threat in `docs/security/scoring.md` is below 4
  (`customer`). A risk whose impact reaches the laboratory's data or its staff, or a
  dispatcher's action, is not accepted; it is a condition or a reason for a no-go.
- **A2.** Its control's stage in `evidence/attack-dev.json` records `held`, or the control
  has no stage in the combined attack. A risk whose control the current run shows as
  `limited` or `failed` is not accepted.

An accepted risk is accepted for now: the decision record names the evidence that would
reopen it.

## What this policy does not decide

The decision is technical: whether the evidence supports relying on this workflow, and under
which conditions. The business decision on the laboratory's renewal, and every medical and
delivery decision, stay with the people who own them. A `go` is not a statement that the
workflow is secure in general; it says that no residual risk in this register blocks relying
on it for the cases the evidence covers.
