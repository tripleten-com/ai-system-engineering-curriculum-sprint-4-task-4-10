<!--
Coldline - Task 4.5
Supplied material: what the security gate scans, what it must fail, and what the three
triage values mean. Not student-editable. The checks read the required thresholds from the
table under "What the gate must fail" and the triage values from the table under "The three
triage values"; keep both shapes if this file is revised.
-->
# Security gate policy

Every pull request against this repository runs the `security-gate` job in
`.github/workflows/security.yml`. The job checks out the pull request's own head commit (not the
merge commit GitHub would build), records which commit that was, and runs `poe security-scan`,
the same command you run locally, over its files: Semgrep for static analysis, Trivy for
dependency and image vulnerabilities, and Gitleaks for secrets. It uploads the scan report
(`scan.sarif`, which names the scanned commit in each run's version-control provenance) and the
software bill of materials (`sbom.cdx.json`) as the `security-reports` artifact of the run, kept
for 90 days, and it fails exactly when the scan exits 1: an unsuppressed finding at or above a
threshold in `security/gate.yaml`.

## What the gate scans

| Scanner | Over | How |
|---|---|---|
| Semgrep | Every Python file Git tracks or would track (not the files `.gitignore` names) | The supplied local rules in `security/semgrep-rules.yaml` only, metrics off, no registry fetch, `.semgrepignore` applied, inline `nosemgrep` markers not honoured (a finding leaves the report when the construct leaves the file) |
| Trivy | `uv.lock`, the dependency set of both first-party images, every group; and, on a branch where `poe seed-vulnerable` wrote it, the supplied fixture `security/seed/requirements.txt` | The vulnerability database pinned by digest in `security/scanners.yaml`, downloaded once by `poe security-setup` into `.tools/trivy-cache/<digest prefix>/` beside a marker that records the pinned reference; every scan skips the database update and runs offline, and a cache downloaded for another digest is never reused |
| Gitleaks | The checked-out files, not the commit history (`gitleaks dir`) | `.gitleaks.toml`, which extends the default rules with the Coldline provider-key format and holds this repository's reviewed suppressions |

The three scanner images are pinned by digest in `security/scanners.yaml`; each runs through
`docker run` with the repository's files mounted read-only and the network off, on your machine
and in the hosted job alike.

**Image vulnerabilities.** The dependency set the two first-party images install is `uv.lock`,
so the lockfile scan is the image scan. The gate does not scan the Debian base image's operating
system packages: that image is pinned by digest in the Dockerfiles, its package set is not this
repository's to change, and under the live database it carries high-severity findings that no
pull request here can fix and that would fail every clean tree. That limit is stated here on
purpose; a release pipeline that owns the base image owns that scan too.

**Findings with no fixed version.** The supplied profile counts every finding, fixed or not
(`ignore_unfixed: false` in `security/scanners.yaml`). If a finding with no fixed version is ever
left under the pinned database, the decision to leave it out of the verdict, with `--ignore-unfixed`
and the reason, is recorded here beside the switch; nothing of the kind is recorded today.

**Re-pinning the vulnerability database.** The pinned digest is a published snapshot of
`ghcr.io/aquasecurity/trivy-db`; the registry prunes old snapshots. When `poe security-setup`
reports that the digest is no longer served, the course team re-pins: run the scan once against
the newest snapshot, record every new finding and its triage in this file's history, bump
`trivy_db.digest` in `security/scanners.yaml`, and have every open branch re-run
`poe security-setup`. The new digest names a new cache directory, so no machine goes on
scanning with the old snapshot under the new name. A re-pin is a change to this repository's
supplied material and never part of a Task's permitted diff.

## What the gate must fail

Thresholds live in `security/gate.yaml`, one per scanner, with the allowed values in its comments.
The gate is required to fail on two kinds of finding, and the third threshold is yours to choose
within the allowed values:

| Threshold | Required value | Why |
|---|---|---|
| `secrets` | `any` | A credential in the repository is exposed to every clone, fork and old commit; there is no severity below which that is acceptable |
| `dependencies` | `high` | A known vulnerability of high or critical severity in a dependency the images install is a weakness every deployment ships |
| `static_analysis` | `high` or `critical` | Which static-analysis severity should block a merge is a judgement about this codebase and its reviewers; state your reason in the Task 7 evidence index and defend it at the Project Defense |

`none` leaves a scanner report-only, which is how the file is supplied and not how it may stay.
A threshold does not change what the scanners find or print: `poe security-scan` prints every
finding, whatever its severity, with its stable id, and marks the ones at or above a threshold.

Severities on one scale, `low`, `medium`, `high`, `critical`: Trivy's own severities map to it
directly; Semgrep's `INFO`, `WARNING` and `ERROR` map to `low`, `medium` and `high`; a Gitleaks
finding has no severity, it is a secret.

## Finding ids

Every finding `poe security-scan` prints carries an id of the form `F-nn`: `F-` and two digits
derived from the finding's content, the scanner, the rule and the file, so it is the same on
every machine and does not change when other lines of the file, or other files, change; a
finding's id on your working branch is its id on the starting checkpoint, in the scan with no
allowlist applied, in the seeded scans and in the hosted job. The width is fixed: if two findings
of one scan ever share an id, the scan stops and says so, and widening the ids is a course-team
change made everywhere at once (this policy, the answer schema, the keys), never a change to one
finding's id in one report. The scan prints findings in numeric id order. One finding is one rule
reported in one file; when a rule matches several places in one file, the finding lists every
line and keeps one id. A suppression that removes a finding removes its id from the report; a fix
does the same.

## The three triage values

Every finding on your working branch needs one recorded triage value in `answers.triage` of
`submission.yaml`, keyed by the finding's id, whatever its severity and whether or not it fails
the gate. The values:

| Value | Meaning | What follows |
|---|---|---|
| `valid` | The rule matched, and the weakness the rule describes is present in this code: the matched construct does what the rule warns against, on input or data the code does not fully control | Fix it in the file the finding names, following the rule's own recommendation, and record its id in `answers.fixed_finding` |
| `false_positive` | The rule matched, but what it matched is not what the rule is about: the matched text or construct is not the kind of thing the rule exists to find. For a secret rule that is a matched value that is no credential at all, or a development credential that only a component of this local stack accepts and that nothing outside the stack honours: every party that would accept it runs inside the stack, so a copy of it grants nothing anywhere the stack does not run. A credential with authority outside this stack, whatever it is called, however old it is and whatever it was made for, is never a false positive | Suppress it, scoped to the finding's rule and the single path it names, with a comment that names the finding id, says why the match is safe, and gives the date you decided; record its id in `answers.suppressed_finding` |
| `accepted` | The rule matched, the construct is what the rule describes, and the team has decided it needs no change here, because the weakness the rule warns against reaches nothing this system protects in that use, and that reasoning is recorded | Leave the code and the report as they are: no fix, no suppression. The finding stays visible on every scan, below the threshold, with its triage on record |

A finding is `valid` or `accepted` by what the matched code does with what input, not by how
much work the fix is; a finding is `false_positive` only when the match itself is wrong, not when
the weakness is real but tolerated. For a secret finding the question is who honours the value:
a development credential that only this stack's own components accept is a wrong match for a
rule that exists to find credentials with authority somewhere, and one that any system outside
the stack honours is a right match, whatever else is true of it. When a rule matches more than
one place, triage the finding as the rule reports it: one id, one value.

## The suppression

A suppression is one top-level `[[allowlists]]` entry in `.gitleaks.toml`, scoped to one rule
and one path, with the comment described above directly over it. The entry:

```toml
# F-nn: <why this match is safe>. Decided <YYYY-MM-DD>.
[[allowlists]]
targetRules = ["<rule id>"]
paths = ['''^<the file's path, every special character escaped>$''']
```

The entry holds exactly those two keys. `targetRules` names the finding's rule and nothing else.
`paths` holds one pattern: the file's path anchored with `^` and `$`, with every regex special
character escaped (`\.` for the dot of its extension, as Python's `re.escape` writes it), as a
TOML literal string (`'''...'''`) or as an equivalent basic string with the backslash doubled. An
entry that names a rule and no path suppresses that rule everywhere; one that names a path and
no rule suppresses every rule in that file; an unanchored path, a wildcard, a directory prefix or
an alternation (`^this\.yaml$|^some-directory/`) reaches files that do not exist yet; a
`regexes`, `stopwords`, `commits`, `condition`, `regexTarget` or `description` key beside the two
widens or blurs what the entry hides. Each of those leaves later findings unseen, and the public
check refuses them. Everything else in the file stays exactly as supplied: the public check
parses the file, sets the one entry aside, and compares what is left with the supplied
configuration (the title, `useDefault = true` and the supplied provider-key rule with its regex
and keywords); a disabled default rule, a second extension setting or a second rule table is a
finding. `poe seed-secret` writes a key in the supplied rule's format, and the gate must find it.
The `[[rules]]` plus `[[rules.allowlists]]` form Gitleaks also accepts is not accepted here, for
the same reason: it changes the supplied part of the file. An inline `gitleaks:allow` comment
beside a match is no suppression either: the scanner runs with `--ignore-gitleaks-allow`, in the
ordinary scan and in the inventory scan alike, as Semgrep runs with `--disable-nosem`, so a
finding leaves the report only when the construct leaves the file or the one reviewed entry
covers it.

## Demonstration branches

`poe seed-secret` writes a supplied fake key, in the Coldline provider-key format, to
`security/seed/provider-key.txt`; `poe seed-vulnerable` writes the supplied vulnerable fixture,
a pinned release with a published high-severity vulnerability, to
`security/seed/requirements.txt`. Both paths lie outside the permitted files and outside any
path a suppression may name. Each seed goes on its own draft branch from your Step 3 commit, is
pushed, fails the gate, is reverted, passes the gate, and the branch is closed without merging:
after the revert the gate passes, because it scans the files at the head, while the fake key
stays in that branch's history, which is why the branch never merges. `poe verify` applies each
seed to a temporary copy of your tree, scans the copy, and leaves your files alone.

## What the gate does not show

The scanners find what their rules and their database cover, at the versions pinned here, and
nothing else: an absent finding is not an absent weakness. The gate reads the files at the pull
request's head, so a secret removed in a later commit is not reported, though it stays in the
history of every clone that fetched it; a leaked value is replaced, not un-leaked. A threshold
set above a finding leaves the finding visible and the merge unblocked; a suppression hides a
finding from the verdict, not from the file. The hosted job's verdict depends on
`security/gate.yaml` and `.gitleaks.toml` at the pull request's head, both of which a pull
request can change, which is why both are reviewed files and why the triage of every finding is
recorded beside them.
