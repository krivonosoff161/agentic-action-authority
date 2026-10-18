# Agentic Action Authority

**Approve one exact agent action. Reject changed bytes. Recover without replay.**

A small, host-integrated Python component for applications where an AI proposes
a document but an operator must approve its exact content and destination before
the application writes it. No model or network call is in the approval path.

The first supported effect is a **create-only UTF-8 file**, through the optional
[Agentic Security Harness](https://github.com/krivonosoff161/agentic-security-harness)
adapter. The approval core can be installed without Harness; custom effect adapters
are trusted application code and require their own effect/recovery tests.

Version **0.1.1** is an experimental API. Check [Releases](https://github.com/krivonosoff161/agentic-action-authority/releases)
and [PyPI](https://pypi.org/project/agentic-action-authority/0.1.1/) for publication
status. Installing does not enroll an operator or authorize an action.

The `DocumentHost` onboarding facade described below is a **branch candidate**, not
part of the published 0.1.1 wheel. Choose the published route for the released
API, or build and verify the exact candidate checkout before using that facade.

## What it changes

Your agent proposes text. Your host fixes the action, destination, policy,
dependency digests and deadline. An operator reviews the exact request and signs
it outside the agent's environment. The host verifies that signature before
admitting one attempt. Changed text, an old approval or a repeated submission
cannot silently become a new authorized action.

This is **not a content filter**: approval does not prove that text is true or
free of prompt injection. It is not a sandbox for arbitrary Python or a compromised
host, and does not promise universal exactly-once effects. See [security boundaries](https://github.com/krivonosoff161/agentic-action-authority/blob/v0.1.1/SECURITY.md).

## Start with one document

Requirements: Python 3.11; lock targets are Windows x64 and Linux x86_64 with
glibc 2.28+. Use a local filesystem with working SQLite locks, not an unverified
network/FUSE filesystem. For a published wheel, use a new virtual environment:

```text
python -m venv .venv
# Use .venv/Scripts/python.exe on Windows, .venv/bin/python on Linux.
<python> -m pip install "agentic-action-authority[harness]==0.1.1"
<python> -m pip check
```

Omit `[harness]` for the standalone approval core. The file adapter deliberately
pins Harness **1.14.2**. Other Harness versions are not automatically a supported
pairing; compatibility evidence belongs to the exact installed checks below.

### Candidate onboarding API

`DocumentHost` composes the installed create-only file path for a trusted host.
It requires an operator fingerprint obtained through an independent trusted
channel and the host application's owner/repository plus exact revision. These
are bound declarations, not remote Git attestation. The host prepares the task,
transfers exact request and content for separate operator signing, applies the
decision, and gives the agent only a content-only callback. It never generates
an operator key or signs on the agent's behalf.

For this branch candidate, record the exact source commit, build its wheel, use
the hash-locked checkout installation below in a fresh environment, and verify
the installed wheel against that source. The candidate currently retains 0.1.1
package metadata; its filename and version do **not** mean that PyPI's 0.1.1
wheel contains `DocumentHost`. Do not use the PyPI install command above for
the [candidate integration guide](docs/integration.md) or the updated
[one-document path](docs/one-document.md). The
[external developer exercise](docs/user-pilot.md) is a proposed evaluation,
not a completed user study. The [approval alternatives](docs/alternatives.md)
compare documented native HITL and Git review contracts with this candidate;
they do not report benchmark or adoption results.

For an auditable checkout build and hash-locked installation of the exact
source currently checked out:

```text
python -m venv .venv
# Use .venv/Scripts/python.exe on Windows, .venv/bin/python on Linux.
<python> -m pip --isolated install --require-hashes -r requirements/build.txt
<python> -m build --no-isolation --wheel --outdir dist
<python> -m pip --isolated install --only-binary=:all: --require-hashes -r requirements/<windows-or-linux>.txt
<python> -m pip --isolated install --no-index --no-deps dist/agentic_action_authority-0.1.1-py3-none-any.whl
<python> -m pip check
```

For the Harness-free core, use `requirements/core-windows.txt` or
`requirements/core-linux.txt` instead. The file CLI needs the optional Harness
dependency; the core alone does not supply a file writer.

Follow the [one-document guide](https://github.com/krivonosoff161/agentic-action-authority/blob/v0.1.1/docs/one-document.md): prepare → review/sign →
apply decision → write → read back. Operator signing is interactive. Private keys
and passphrases never belong in chat, an agent prompt or command-line arguments.

That versioned link is the **published 0.1.1 guide**. The current checkout's
[one-document guide](docs/one-document.md) covers the candidate flags and
recovery routes and requires the candidate wheel above.

## Embed in your agent application

The routing example [content_only_dispatch.py](https://github.com/krivonosoff161/agentic-action-authority/blob/v0.1.1/examples/content_only_dispatch.py)
accepts only `submit_approved_document({"content": "..."})`, rejects paths and
approval fields, and reports uncertainty without retrying. The host creates and
retains an `ActionGate`, enrolls the operator public key and applies signed
decisions separately. Give the model only the content-only callback, not the
gate, signer or unrestricted filesystem/Python access.

See [architecture and adapter contract](https://github.com/krivonosoff161/agentic-action-authority/blob/v0.1.1/docs/architecture.md) for `ActionCore`,
`ActionGate`, protocol domains, state transitions and adapter obligations.
For this branch candidate's public `DocumentHost` integration, use the
[integration guide](docs/integration.md), not private host helpers.

## Verification and provenance

The [verification guide](https://github.com/krivonosoff161/agentic-action-authority/blob/v0.1.1/docs/verification.md) separates base-only installation,
optional-adapter checks, source/wheel byte identity and platform results. Tests
use disposable signatures and files; they do not constitute human acceptance.
The [source provenance](https://github.com/krivonosoff161/agentic-action-authority/blob/v0.1.1/docs/provenance.md) identifies the original Harness
candidate. Historical results are not automatically results for this distribution.
The [release procedure](https://github.com/krivonosoff161/agentic-action-authority/blob/v0.1.1/docs/releasing.md) binds one tag-built wheel to staging,
publication and downloaded-index checks; a read-only check is not an upload.

One project owns the approval core here. Harness owns its file writer and broader
security laboratory. There is no second copied writer or circular dependency.
Apache-2.0; see [LICENSE](https://github.com/krivonosoff161/agentic-action-authority/blob/v0.1.1/LICENSE)
and [NOTICE](https://github.com/krivonosoff161/agentic-action-authority/blob/v0.1.1/NOTICE).
