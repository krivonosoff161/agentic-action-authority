# Source provenance

This project originates in the separately packaged Action Authority candidate in
[Agentic Security Harness PR374](https://github.com/krivonosoff161/agentic-security-harness/pull/374).
The exact extraction source is commit
`da1292146b882e613992f6a4ef1d0cd8653c1d69`, directory `packages/action-authority`.
Source, synthetic tests, example and acceptance tools were imported from tracked
Git objects. Apache-2.0 license and original NOTICE attribution are retained.

The previous candidate was named `ash-action-authority-candidate 0.1.0.dev0`.
This repository owns the `agentic-action-authority` distribution and retains the
`ash_action_authority` Python namespace. It is not the old candidate wheel.
Versioned v1 file requests retain their signing domain and schema; generic host
bindings have their own versioned domain. Existing runtime state is not silently
migrated. Never replace a previously installed candidate underneath an active
operator task; complete or fence it using its original verified environment.

The Harness create-only writer is not copied here. The optional file adapter
delegates to the separately released Harness package. Harness integration tests
may consume this distribution but the Harness base package must not require it,
preventing a circular installation dependency.

Previous candidate test and owner-acceptance results describe their original
revision. They are provenance, not proof that this extracted version passed.
Each release needs its own source/wheel hashes and installed checks; see the
[0.3.0 release record](releases/v0.3.0.md) for the current exact subject and gates.
Real owner approvals, signing keys, documents and private research are excluded.
