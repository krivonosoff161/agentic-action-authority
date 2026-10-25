# Agentic Action Authority

**Approve one exact agent action. Reject changed bytes. Recover without replay.**

A small, host-integrated Python component for applications where an AI proposes
a document but an operator must approve its exact content and destination before
the application writes it. No model or network call is in the approval path.

The first supported effect is a **create-only UTF-8 file**, through the optional
[Agentic Security Harness](https://github.com/krivonosoff161/agentic-security-harness)
adapter. The approval core can be installed without Harness; custom effect adapters
are trusted application code and require their own effect/recovery tests.

This is the **0.3.0 API**: `DocumentHost` lets the trusted host execute the
retained, reviewed document after a separate signed decision, without asking a
model or caller to resubmit its text. Check the [0.3.0 package page](https://pypi.org/project/agentic-action-authority/0.3.0/)
and [release evidence](https://github.com/krivonosoff161/agentic-action-authority/releases/tag/v0.3.0)
before treating an index install as available or a release as complete. Source
metadata and this README do not prove publication. Installing never enrolls an
operator or authorizes an action. See the [0.3.0 scope](https://github.com/krivonosoff161/agentic-action-authority/blob/v0.3.0/docs/releases/v0.3.0.md).

## What it changes

Your agent proposes text. Your host fixes the action, destination, policy,
dependency digests and deadline. An operator reviews the exact request and signs
it outside the agent's environment. The host verifies that signature before
admitting one attempt. Changed text, an old approval or a repeated submission
cannot silently become a new authorized action.

This is **not a content filter**: approval does not prove that text is true or
free of prompt injection. It is not a sandbox for arbitrary Python or a compromised
host, and does not promise universal exactly-once effects. See [security boundaries](https://github.com/krivonosoff161/agentic-action-authority/blob/v0.3.0/SECURITY.md).

## Start with one document

Requirements: Python 3.11; lock targets are Windows x64 and Linux x86_64 with
glibc 2.28+. Use a local filesystem with working SQLite locks, not an unverified
network/FUSE filesystem. After confirming 0.3.0 is available on the index,
use a new virtual environment:

```text
python -m venv .venv
# Use .venv/Scripts/python.exe on Windows, .venv/bin/python on Linux.
<python> -m pip install "agentic-action-authority[harness]==0.3.0"
<python> -m pip check
```

Omit `[harness]` for the standalone approval core. The file adapter deliberately
pins Harness **1.14.2**. Other Harness versions are not automatically a supported
pairing; compatibility evidence belongs to the exact installed checks below.

### DocumentHost onboarding API in 0.3.0

`DocumentHost` composes the installed create-only file path for a trusted host.
It requires an operator fingerprint obtained through an independent trusted
channel and the host application's owner/repository plus exact revision. These
are bound declarations, not remote Git attestation. The host prepares the task,
transfers exact request and content for separate operator signing, applies the
decision, and calls `host.execute_approved()` itself. It never generates an
operator key or signs on the agent's behalf. The content-only callback remains
available for applications that need the 0.2.0 integration shape.

Use the [integration guide](https://github.com/krivonosoff161/agentic-action-authority/blob/v0.3.0/docs/integration.md)
or [one-document path](https://github.com/krivonosoff161/agentic-action-authority/blob/v0.3.0/docs/one-document.md)
with a verified 0.3.0 installation. Setup requires
`--expected-key-fingerprint` and `--host-repository` on the CLI (or
`expected_key_fingerprint` and `host_repository` in Python). An existing 0.1.1 task is not
automatically migrated or overwritten; see the [0.1.1 to 0.2.0 upgrade notes](https://github.com/krivonosoff161/agentic-action-authority/blob/v0.3.0/docs/upgrading-0.2.md).
The [external developer exercise](https://github.com/krivonosoff161/agentic-action-authority/blob/v0.3.0/docs/user-pilot.md)
is proposed, not completed. The [approval alternatives](https://github.com/krivonosoff161/agentic-action-authority/blob/v0.3.0/docs/alternatives.md)
compare documented contracts, not benchmark or adoption results.

For an auditable checkout build and hash-locked installation of the exact
source currently checked out:

```text
python -m venv .venv
# Use .venv/Scripts/python.exe on Windows, .venv/bin/python on Linux.
<python> -m pip --isolated install --require-hashes -r requirements/build.txt
<python> -m build --no-isolation --wheel --outdir dist
<python> -m pip --isolated install --only-binary=:all: --require-hashes -r requirements/<windows-or-linux>.txt
<python> -m pip --isolated install --no-index --no-deps dist/agentic_action_authority-0.3.0-py3-none-any.whl
<python> -m pip check
```

For the Harness-free core, use `requirements/core-windows.txt` or
`requirements/core-linux.txt` instead. The file CLI needs the optional Harness
dependency; the core alone does not supply a file writer.

Follow the [one-document guide](https://github.com/krivonosoff161/agentic-action-authority/blob/v0.3.0/docs/one-document.md): prepare → review/sign →
apply decision → write → read back. Operator signing is interactive. Private keys
and passphrases never belong in chat, an agent prompt or command-line arguments.

The [0.2.0](https://github.com/krivonosoff161/agentic-action-authority/blob/v0.2.0/docs/releases/v0.2.0.md) and [0.1.1](https://github.com/krivonosoff161/agentic-action-authority/blob/v0.1.1/docs/releases/v0.1.1.md)
release records remain historical evidence. The 0.2.0 wheel has `DocumentHost`
and the content callback but does not have `execute_approved()`.

## Embed in your agent application

The preferred 0.3.0 route is [host-only approved execution](https://github.com/krivonosoff161/agentic-action-authority/blob/v0.3.0/docs/approved-execution.md):
after applying the signed decision, the trusted host calls
`DocumentHost.execute_approved()` and then `status(recover=True)`. The operator
CLI labels the destination and deadline before full exact review. Neither call
is an agent tool or an automatic approval.

The compatibility routing example [content_only_dispatch.py](https://github.com/krivonosoff161/agentic-action-authority/blob/v0.3.0/examples/content_only_dispatch.py)
accepts only `submit_approved_document({"content": "..."})`, rejects paths and
approval fields, and reports uncertainty without retrying. The host creates and
retains an `ActionGate`, enrolls the operator public key and applies signed
decisions separately. Give the model only the content-only callback, not the
gate, signer or unrestricted filesystem/Python access.

See [architecture and adapter contract](https://github.com/krivonosoff161/agentic-action-authority/blob/v0.3.0/docs/architecture.md) for `ActionCore`,
`ActionGate`, protocol domains, state transitions and adapter obligations.
For `DocumentHost` integration, use the
[integration guide](https://github.com/krivonosoff161/agentic-action-authority/blob/v0.3.0/docs/integration.md), not private host helpers.
The `content_only_dispatch.py` example is the lower-level `ActionGate`
compatibility route; `DocumentHost` is the shorter public host composition.

## Proposed Agent Framework integration (not in the 0.3.0 release)

The optional [declaration-only document adapter](docs/agent-framework.md) connects
one native pending tool call to the existing signed, retained-document action.
It includes an offline Agent/Workflow example and a separate installed SDK test
lane. This is an integration proposal in this checkout, not Microsoft acceptance,
an arbitrary-tool executor, or a feature of the published 0.3.0 wheel.

## Verification and provenance

The [verification guide](https://github.com/krivonosoff161/agentic-action-authority/blob/v0.3.0/docs/verification.md) separates base-only installation,
optional-adapter checks, source/wheel byte identity and platform results. Tests
use disposable signatures and files; they do not constitute human acceptance.
The [0.3.0 release page](https://github.com/krivonosoff161/agentic-action-authority/releases/tag/v0.3.0)
and index receipts must establish the exact published bytes; the
[version scope](https://github.com/krivonosoff161/agentic-action-authority/blob/v0.3.0/docs/releases/v0.3.0.md) does not itself prove an upload.
The [source provenance](https://github.com/krivonosoff161/agentic-action-authority/blob/v0.3.0/docs/provenance.md) identifies the original Harness
candidate. Historical results are not automatically results for this distribution.
The [release procedure](https://github.com/krivonosoff161/agentic-action-authority/blob/v0.3.0/docs/releasing.md) binds one tag-built wheel to staging,
publication and downloaded-index checks; a read-only check is not an upload.

One project owns the approval core here. Harness owns its file writer and broader
security laboratory. There is no second copied writer or circular dependency.
Apache-2.0; see [LICENSE](https://github.com/krivonosoff161/agentic-action-authority/blob/v0.3.0/LICENSE)
and [NOTICE](https://github.com/krivonosoff161/agentic-action-authority/blob/v0.3.0/NOTICE).
