# Verify a specific build

Use separate fresh virtual environments for core and Harness lanes. Install
hash-locked dependencies first, then the SAME wheel with --no-index --no-deps.
Run pip check. The core lane must not have Harness installed.

From OUTSIDE the checkout, using absolute paths and new output destinations:

```text
<core-python> <checkout>/tools/check_installed_wheel.py --wheel <wheel> --source <checkout> --out core-wheel.json
<core-python> <checkout>/tools/run_checks.py --source <checkout> --suite core --out core-checks
<harness-python> <checkout>/tools/check_installed_wheel.py --wheel <wheel> --source <checkout> --with-harness --out adapter-wheel.json
<harness-python> <checkout>/tools/run_checks.py --source <checkout> --suite harness --out adapter-checks
```

The runner checks an explicit source/test/example inventory and installed imports.
Expected counts: core28, Harness72 (includes core). No skipped/expected-failure
test is accepted. Counts are bookkeeping, not a security score.

The wheel checker compares source, wheel RECORD and installed bytes. CI builds
one wheel and installs those bytes on Windows/Linux in both lanes. Results bind
hashes, platform, Python, test-file hashes and outcomes to a commit. Do not combine
revisions or infer Linux from Windows. Retain failed attempts and their repairs.

Cases cover schema/signature negatives, changed/replayed bytes, revocation/expiry,
two-process serialization, actual child-process interruption, receipt/readback
divergence, storage-error injection and real temporary writes.
All keys, signatures and effects are disposable synthetic fixtures, not operator
consent. Tests make no model calls; network syscall isolation is not established
by this suite. Assistant review is not independent human review.

For an audit retain commit, wheel SHA-256, locks, commands, result JSON and limits.
Do not publish private keys, decisions, real documents, runtime state or raw
operator transcripts. Public CI artifacts contain synthetic test summaries and
bounded fixture diagnostics only.
