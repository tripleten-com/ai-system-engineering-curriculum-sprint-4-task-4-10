<!--
Coldline - Task 4.6
Supplied material: the roles that can own a risk in the register, and the rule that says
which one owns a given risk. Not student-editable. The checks read the role ids from the
first column of the table; keep its shape if this file is revised.
-->
# Risk owners

A risk's owner is the role that can act on the risk when it changes: the role that decides
what happens to what the control leaves over. That is not always the role that built the
control. The register's `owner` field takes one role id from the table below.

## The roles

| Role id | Role | What the role can decide |
|---|---|---|
| `platform-lead` | Platform engineering lead | Changes to Coldline's code, configuration, pipeline and dependencies, and when a change ships |
| `security-reviewer` | Security reviewer | What further test, review or attack case is needed before a limit of the tested cases can be called closed |
| `privacy-lead` | Privacy lead | How personal data that remains in a store, a log or a request is handled, kept and disclosed |
| `dispatch-lead` | Dispatch operations lead | What dispatchers rely on, and what they review by hand before anyone acts on a summary |

## Who owns a risk

Read the residual risk you wrote for the entry, and apply the first rule that fits it:

1. Personal data remains somewhere with the control in place (a store, a log line, a request,
   a record): `privacy-lead`.
2. A person must still review or decide before anyone acts, with the control in place:
   `dispatch-lead`.
3. A change to Coldline's code, configuration, pipeline or dependencies would close or narrow
   what remains: `platform-lead`.
4. Otherwise, what remains is a limit of what the tested cases establish: `security-reviewer`.

The rule looks at the residual, not at the control's name: two entries with controls built by
the same team can have different owners, and an owner can own a risk whose control they did
not build. Write the residual first, then choose.
