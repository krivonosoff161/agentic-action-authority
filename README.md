# Agentic Action Authority

**Approve one exact agent action. Reject changed bytes. Recover without replay.**

A small, host-integrated Python component for applications where an AI proposes
a document but an operator must approve its exact content and destination before
the application writes it. No model or network call is in the approval path.

The first supported effect is a **create-only UTF-8 file**, through the optional
[Agentic Security Harness](https://github.com/krivonosoff161/agentic-security-harness)
adapter. The approval core can be installed without Harness; custom effect adapters
are trusted application code and require their own effect/recovery tests.

Version **0.1.0** is an experimental API. Check [Releases](https://github.com/krivonosoff161/agentic-action-authority/releases)
for publication status; these commands build this checkout without assuming an
index package has been published.

## What it changes

Your agent proposes text. Your host fixes the action, destination, policy,
dependency digests and deadline. An operator reviews the exact request and signs
it outside the agent's environment. The host verifies that signature before
admitting one attempt. Changed text, an old approval or a repeated submission
cannot silently become a new authorized action.

This is **not a content filter**: approval does not prove that text is true or
free of prompt injection. It is not a sandbox for arbitrary Python or a compromised
host, and does not promise universal exactly-once effects. See [security boundaries](SECURITY.md).

## Start with one document

Requirements: Python 3.11; lock targets are Windows x64 and Linux x86_64 with
glibc 2.28+. Use a local filesystem with working SQLite locks, not an unverified
network/FUSE filesystem. Build in a new virtual environment from this checkout:

```text
python -m venv .venv
# Use .venv/Scripts/python.exe on Windows, .venv/bin/python on Linux.
<python> -m pip --isolated install --require-hashes -r requirements/build.txt
<python> -m build --no-isolation --wheel --outdir dist
<python> -m pip --isolated install --only-binary=:all: --require-hashes -r requirements/<windows-or-linux>.txt
<python> -m pip --isolated install --no-index --no-deps dist/agentic_action_authority-0.1.0-py3-none-any.whl
<python> -m pip check
```

For the Harness-free core, use `requirements/core-windows.txt` or
`requirements/core-linux.txt` instead. The file CLI needs the optional Harness
dependency; the core alone does not supply a file writer.

Follow the [one-document guide](docs/one-document.md): prepare → review/sign →
apply decision → write → read back. Operator signing is interactive. Private keys
and passphrases never belong in chat, an agent prompt or command-line arguments.

## Embed in your agent application

The routing example [content_only_dispatch.py](examples/content_only_dispatch.py)
accepts only `submit_approved_document({"content": "..."})`, rejects paths and
approval fields, and reports uncertainty without retrying. The host creates and
retains an `ActionGate`, enrolls the operator public key and applies signed
decisions separately. Give the model only the content-only callback, not the
gate, signer or unrestricted filesystem/Python access.

See [architecture and adapter contract](docs/architecture.md) for `ActionCore`,
`ActionGate`, protocol domains, state transitions and adapter obligations.

## Verification and provenance

The [verification guide](docs/verification.md) separates base-only installation,
optional-adapter checks, source/wheel byte identity and platform results. Tests
use disposable signatures and files; they do not constitute human acceptance.
The [source provenance](docs/provenance.md) identifies the original Harness
candidate. Historical results are not automatically results for this distribution.

One project owns the approval core here. Harness owns its file writer and broader
security laboratory. There is no second copied writer or circular dependency.
Apache-2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
