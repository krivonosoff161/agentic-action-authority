# Architecture and adapter obligations

The dependency direction is one-way:

```text
trusted host -> ActionCore -> cryptographic protocol + local approval state
                   |
                   v trusted effect interface
              ActionGate's Harness adapter -> installed Harness writer
operator device -> signed decision -> host verification
agent -> content-only submit callback
```

The base distribution imports ActionCore, AuthorityError and protocol helpers
without Harness. Importing ActionGate loads the optional file adapter. The operator
CLI is never an agent tool. The host CLI is the file adapter's reference host,
not an unrestricted execution server.

Version 0.2.0 adds public `DocumentHost` as an installed facade over this
existing host state and writer; 0.1.1 did not contain it. `prepare` validates
an independently supplied expected
public-key fingerprint before task creation, then binds a host-declared
`owner/repository` and exact host revision. Structural validation does not
prove remote repository provenance. Version 0.2.0 requires these fingerprint
and host-repository inputs; old task state is not migrated or overwritten.
See the [upgrade notes](upgrading-0.2.md). `open` reopens retained state without
recreating it; `review_files`, `request`, and `export_request` let the trusted
host transfer an exact review. `apply_decision` remains host-only. `bind_tool`
exposes only `submit_approved_document({"content": ...})`; `status(recover=True)`
performs readback or fencing without delivery. See the [integration guide](integration.md).

The **unreleased checkout** additionally exposes `execute_approved()` on the trusted
host facade. It restores and submits the retained exact document, using the same
route as the existing host CLI. It is not registered as a model tool and does not
approve, choose a path, normalize bytes or replay a spent attempt. The compatibility
content callback and the underlying core/writer contracts are unchanged. See
[approved execution](approved-execution.md) for the code argument and limits.

## Approval binding

File v1 binds app/task/operation/initiator, exact UTF-8 hash and length,
destination identity/path, policy/source-admission digests, declared dependencies,
operator public-key fingerprint, deadline, epoch and random challenge.
Generic v2 has a separate signature domain, with action/target/effect-contract
digest replacing file-specific fields. Unknown fields are rejected.
File and generic signatures are not interchangeable. Returned nested binding
copies cannot mutate approval; live adapter-binding changes are rejected.

Digests pin declared objects. They do not discover omitted dependencies or
observe external changes by themselves. The host supplies those observations
and invalidates required context before using changed inputs.

## Coordinator

`ActionCore.create(root, effect, content=..., public_key=..., key_id=...,
app_id=..., task_id=..., initiator=..., expires_at=...)` creates NEW state.
Open requires the same binding. The host retains configuration.
Request, apply_decision and invalidate belong on the host/operator side.
Only submit(content) belongs on the agent side.

SQLite serialization orders approval, revocation and one execution attempt.
PENDING_APPROVAL -> APPROVED -> EXECUTING spends admission at the durable BEGIN.
Errors after that point are uncertain, not new permission. Revocation before BEGIN
rotates epoch/challenge; after BEGIN it does not acknowledge cancellation.
An expired request needs a new task and review. An accepted pre-BEGIN revoke
needs a newly exported request and signed decision. Neither `UNKNOWN` nor an
interrupted call permits replay of the old action.
Bounded control-log capacity is checked before effects; history is not truncated.

Status is historical. Recover verifies/fences using the trusted adapter and never
calls delivery. Coordinated rollback, compromised host, unsupported filesystem
power-loss behavior and distributed transactions are outside the contract.

## A custom effect is not merely a callback

EffectPort supplies binding, max_bytes, request_domain, check(),
create(state_path), open(state_path) and target_absent().
The opened operation supplies authorize(), deliver(permission) and fence().

The adapter must durably spend one permission, bind the intended effect, never
deliver from fence, prevent stale executors after fencing, and distinguish verified
postcondition, verified absence and uncertainty. It owns the regular, unlinked
operation.sqlite path required by this coordinator. Revalidate effect preconditions
at execution, not just construction. An effect_contract_sha256 is a version pin,
not proof that these obligations hold.

Return DELIVERED_RECEIPT with a writer_receipt, RECONCILED_POSTCONDITION,
FENCED_ABSENT or UNKNOWN, plus a fixed reason. Malformed success becomes UNKNOWN;
a dishonest trusted adapter can still lie. The core does not attest arbitrary
adapters. The generic fixture is synthetic, not a second supported backend.
Database/email/payment/remote API adapters are not shipped. Each needs its own
binding, crash, concurrency and recovery/readback evidence.

The shipped effect adapter uses Harness create-only file writing. No second writer
is copied here. See SECURITY.md and provenance.md before making broader claims.
