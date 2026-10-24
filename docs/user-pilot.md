# Bounded external developer exercise

This is a **proposed exercise**, not a completed pilot or independent human
acceptance. Use a precisely identified 0.3.0 wheel after verifying its
availability and release evidence; 0.2.0 lacks `execute_approved()`. Give participants that wheel, the
[integration guide](integration.md), disposable public source and document
fixtures, and a separate operator role with synthetic keys. Do not use real
keys, private documents, provider credentials, or production destinations.

## Scenario and equal baseline

Ask a Python application developer to integrate a create-only reviewed UTF-8
document from proposed text. The operator must inspect exact content and
destination and approve outside the agent's environment. Test these same
events for each approach: initial approval, changed document after approval,
second submission, expiry before admission, revocation before and after BEGIN,
and interruption with uncertain outcome.

Compare three approaches under the same trust and filesystem assumptions:

| Approach | What the participant may use | What must be evaluated |
|---|---|---|
| Existing native approval | Their framework's human approval mechanism plus a trusted host callback | How it binds the exact document and destination, stores/rechecks decisions, prevents repeated effects, and recovers after interruption. |
| Git review | A normal protected PR/review flow where the document is a reviewed repository change | Whether stale approval is dismissed after a changed diff and whether the actual target action is fully covered by that repository workflow. |
| Action Authority 0.3.0 | Installed `DocumentHost.execute_approved()`, separate operator CLI, optional Harness writer | Whether host-only retained execution reduces integration work while preserving exact binding, one attempt, and conservative recovery. The content callback remains a compatibility option. |

Do not assume the baselines are weak. A sound native callback can implement the
same checks; a repository document may already be sufficiently governed by Git
review. If either baseline covers the user's actual action with less work,
record that result. No comparative superiority has been measured here.

## Tasks and observations

Give the same written task and fixtures to each participant without private
coaching. Ask them to choose the appropriate install route, obtain a separately
verified fingerprint, declare the host repository/revision, prepare a request,
complete independent operator review, execute from trusted retained host state
and inspect readback. If they choose the compatibility callback, record the extra
caller-side read, UTF-8 decode and exact-content submission.
Then present changed bytes, a repeat, expiry and an interrupted attempt. Ask
them to explain when to create a new task and when to stop on `UNKNOWN`.

For each participant and approach, record:

- elapsed time to first verified file receipt and to completion of recovery;
- commands or integration steps, host code written, and help requests;
- refusals, wrong assumptions, unsafe workarounds, and whether the operator
  remained independent of the agent;
- whether the participant would choose this approach for their own applicable
  workflow, with the reason and work saved or added.

A small initial target is three external Python developers; a provisional
usability target is two reaching the first verified result within one hour
without private author assistance or weakened controls. This is a target, not
an observed result or evidence of broad demand. Preserve failed attempts and
distinguish deterministic tests, developer observations, and actual adoption.
Do not store participant correspondence or raw private material in public Git.
