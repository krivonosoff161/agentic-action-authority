# Move a document integration from 0.1.1 to 0.2.0

Version 0.2.0 adds public `DocumentHost` over the existing ActionCore and
Harness 1.14.2 create-only writer. The 0.1.1 wheel does not contain this facade.
Confirm availability and exact installed version before following the
[0.2.0 integration guide](https://github.com/krivonosoff161/agentic-action-authority/blob/v0.2.0/docs/integration.md). This is an API and onboarding change,
not a new effect backend or a claim of generic agent containment.

## New task setup

The host CLI now requires `--expected-key-fingerprint` and `--host-repository`
alongside `--host-revision`. The Python `DocumentHost.prepare` API likewise
requires `expected_key_fingerprint`, `host_repository` and `host_revision`.
The host must receive the expected lowercase SHA-256 public-key fingerprint
through an **independent trusted operator channel**. Computing it from the
received public-key file and passing that value back does not establish
operator identity. The repository is the host application's `owner/repository`;
the revision is that repository's exact host commit. These are bound host
declarations, not remote Git provenance attestation.

Use a new task directory for a new action. Freeze the proposed UTF-8 bytes,
transfer exact request and content for separate operator review, and expose
only the content callback to an agent. On Windows, read approved content with
`read_bytes().decode("utf-8")`; `read_text()` may normalize CRLF to LF and
change the approved bytes.

## Existing 0.1.1 state

Keep existing task directories and their original evidence intact. No automatic
migration, overwrite, or approval carry-forward is promised. Do not run setup
over an old home, copy an old signed decision into a new task, or alter stored
bytes to make a new version accept them. For an unfinished or uncertain 0.1.1
task, retain its original installation and follow its versioned recovery guide;
inspect the outcome before authorizing a separate replacement task. If the
result remains `UNKNOWN`, do not replay the old action.

The historical [0.1.1 release record](releases/v0.1.1.md) remains the evidence
for that wheel. The [0.2.0 GitHub release](https://github.com/krivonosoff161/agentic-action-authority/releases/tag/v0.2.0)
must provide actual tag and index receipts before publication is claimed;
the immutable [version scope](releases/v0.2.0.md) alone is not upload evidence.
