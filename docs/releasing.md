# Release one immutable wheel

Publication requires owner approval, a merged exact revision and an unused
version. Do not replace tags, overwrite index versions, skip existing uploads or
rebuild a different wheel for another index.

Before enabling publication, the owner must configure the `testpypi` and `pypi`
GitHub environments: required reviewer `krivonosoff161`, custom deployment policy
allowing only tags `v0.1.0`, `v0.1.1`, `v0.2.0` (retained history) and `v0.3.0`
(this release).
Adding the new exact tag requires the owner's scoped approval; preserve prior
entries and reviewer protections. Configure each index Trusted Publisher for this
repository's `release.yml` and its matching environment. No API token is stored
in this repository. Naming an environment in YAML does not create these controls;
the release preflight checks live reviewer and exact-tag policy metadata.

1. Merge the checked PR; wait for post-merge checks and Gitleaks.
2. Tag that merged SHA `v0.3.0`. Wait for tag-triggered `checks.yml` AND Gitleaks.
   The tag build makes one wheel and all four Linux/Windows core/adapter lanes
   install that same artifact. Keep the build run ID and SHA-256.
3. Dispatch `release.yml` ON THE TAG with `target=testpypi`, `mode=publish`, and
   that `build_run`. Approve the environment only after reviewing its exact SHA.
   Upload uses OIDC; index readback then runs all four installed lanes.
   The Harness lanes also run the finite route measurement against index bytes.
4. Only a successful TestPyPI **publish** run creates `publication-testpypi`.
   Use its ID as `stage_run` for the PyPI publish dispatch with the SAME build.
   Staging binds the exact repository, workflow, tag, SHA, build ID and wheel hash.
5. After successful PyPI readback and four lanes, publish GitHub release notes
   with links to all exact runs and wheel hash. Attach the original tag artifact,
   not a local rebuild. Retain failed attempts as well as successful evidence.

`mode=verify` performs no upload and emits `index-verification-*`, never a
publication receipt. It cannot authorize promotion to PyPI. If upload succeeded
but a subsequent platform check failed transiently, investigate first, then use
GitHub **Re-run failed jobs** for that same publish run. Do not re-run successful
upload jobs. An ambiguous upload is an owner incident gate, not automatic retry.
Read-only verification does not erase or relabel a failed publication run.

The 0.1.0 TestPyPI upload is retained. Its index check failed because the verifier
decoded UTF-8 description bytes as ASCII replacements, not because the published
wheel changed. The corrected 0.1.1 verifier preserves Unicode and refuses invalid
UTF-8. Never overwrite the old tag or upload a corrected wheel under 0.1.0.

The current release uploads a wheel only; the corresponding source is the immutable
Git tag. Fixed tests use generated fixture keys and documents. Release automation
must never enroll the real operator, sign a decision or use private documents.
