# Verify a specific build

Use separate fresh virtual environments for core, Harness and Agent Framework
lanes on each OS. Install hash-locked dependencies first, then the SAME wheel
with --no-index --no-deps.
Run pip check in each lane. The core lane must not have Harness or Agent
Framework installed; it verifies that the standalone core remains independent.

From OUTSIDE the checkout, using absolute paths and new output destinations:

```text
<core-python> <checkout>/tools/check_installed_wheel.py --wheel <wheel> --source <checkout> --out core-wheel.json
<core-python> <checkout>/tools/run_checks.py --source <checkout> --suite core --out core-checks
<harness-python> <checkout>/tools/check_installed_wheel.py --wheel <wheel> --source <checkout> --with-harness --out adapter-wheel.json
<harness-python> <checkout>/tools/run_checks.py --source <checkout> --suite harness --out adapter-checks
<framework-python> <checkout>/tools/check_installed_wheel.py --wheel <wheel> --source <checkout> --with-harness --out framework-wheel.json
<framework-python> <checkout>/tools/run_checks.py --source <checkout> --suite agent-framework --out framework-checks
```

The runner checks an explicit source/test/example inventory and installed imports.
Version 0.4.0 expected counts per OS: core33, Harness112 (includes core, so
do not add it to core33), Agent Framework14. The framework extra includes
Harness 1.14.2 and `agent-framework-core==1.23.0`. The published
0.2.0 inventory remains core29/Harness93; 0.1.1 remains core28/Harness72.
Do not relabel historical results.
The 0.3.0 inventory adds four operator presentation/CLI checks, seven retained-execution facade
checks, three spawned-process facade checks and five ordinary approval parity checks.
These counts describe the expected 0.4.0 suites, not an actual result or an
update to an older wheel. No skipped/expected-failure test is accepted. Counts
are bookkeeping, not a security score.

The wheel checker compares source, wheel RECORD and installed bytes. CI builds
one wheel and installs those bytes on Windows/Linux in all three lanes per OS.
For index verification, repeat all six installed lanes against the downloaded
release artifact and compare its hash with the recorded release subject before
treating publication as complete. Results bind hashes, platform, Python,
test-file hashes and outcomes to a commit. Do not combine
revisions or infer Linux from Windows. Retain failed attempts and their repairs.

Cases cover schema/signature negatives, changed/replayed bytes, revocation/expiry,
two-process serialization, actual child-process interruption, receipt/readback
divergence, storage-error injection and real temporary writes.
All keys, signatures, client responses and effects are disposable synthetic
fixtures, not operator consent or human acceptance. Tests make no provider/model
calls; network syscall isolation is not established by this suite. Assistant
review is not independent human review.

Version 0.2.0 onboarding cases additionally check independent expected-fingerprint
matching before task creation, explicit host repository/revision declarations,
installed `DocumentHost` public-API composition and content-only routing. Declared
provenance is not remotely attested. Source tests do not replace installed checks.
Version 0.3.0 adds host-only retained execution, operator presentation, spawned
process interruption and an ordinary test-only approval reference. That reference
assumes an authenticated local operator callback and has same-process recovery
checks only; it is not independent human review or a reusable product API.
Version 0.4.0 adds the optional declaration-only Agent Framework route. Its
14-case installed lane checks native pending-call binding, changed-call refusal,
replay prevention and recovery without a second delivery. The offline example
also resumes a new native workflow from a local FileCheckpointStorage checkpoint;
this does not establish behavior for arbitrary workflow stores or exactly-once
response delivery. Synthetic checks are not operator acceptance or Microsoft
endorsement.

For an audit retain commit, wheel SHA-256, locks, commands, result JSON and limits.
Do not publish private keys, decisions, real documents, runtime state or raw
operator transcripts. Public CI artifacts contain synthetic test summaries and
bounded fixture diagnostics only.

The Harness lanes also run the [finite route measurement](approved-execution.md#compare-honestly)
against the same installed wheel. Its numeric timing output has no pass threshold;
exact bytes, unchanged protected content, no replay and verified readback do.
No human usability or model latency is inferred from it.
