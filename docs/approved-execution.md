# Execute the document the operator actually reviewed

**Unreleased source change.** `DocumentHost.execute_approved()` is not in the
published 0.2.0 wheel. Build and verify this checkout using the README's source
installation procedure. Do not install 0.2.0 from the index and expect this method.
No new release or publication is implied by this page.

## The smaller host path

Keep the existing [preparation, independent key enrollment and operator review](integration.md#host-preparation-and-operator-review).
The model proposes a document **before** review. The host retains its exact bytes;
the operator separately reviews the request, destination and full document.
After the signed decision returns, the trusted host can finish without asking
the model to reproduce the reviewed text:

```python
from pathlib import Path
from ash_action_authority import DocumentHost

host = DocumentHost.open(Path("task-001"))
decision = host.apply_decision(Path("approved.json"))
if not decision.get("accepted"):
    raise RuntimeError("operator decision was not accepted")
result = host.execute_approved()  # no document, path or approval argument
readback = host.status(recover=True)
```

This method is **host-only, not an agent tool**. Do not expose the host object,
signer, decision application or unrestricted filesystem to an untrusted agent.
It neither approves the action nor retries an earlier attempt. The existing
content-only callback remains available and keeps its exact-byte checks.

| Result | Meaning and next action |
|---|---|
| `applied / writer_receipt_recorded` | The writer recorded the effect. Inspect current readback; later tampering can invalidate it. |
| `refused / not_approved` | No valid current approval; obtain the separate operator decision. |
| `refused / expired` | Prepare a new task and obtain new approval. |
| `refused / already_consumed` | Do not retry. Inspect the original task and recovery result. |
| `uncertain / host_recovery_required` | An effect may have happened. Preserve the task and recover without delivery. If retained input/state is broken, stop for manual inspection. |

Only the retained document is submitted. Changing or deleting the original proposal
after preparation does not authorize new bytes; changing retained source/document
causes refusal or uncertainty, not execution of the replacement. To approve changed
content, prepare a **new task**. Revocation must reach the host before durable BEGIN;
an in-flight revoke is not a cancellation guarantee.

## Operator presentation, not a different approval protocol

The signing CLI now labels the decision, application/task, destination, byte count
and deadline before displaying the **same full exact request and escaped document**.
All untrusted strings stay escaped, including terminal controls. The operator still
enters the exact confirmation and local passphrase; no summary-only approval,
automatic signature, new key store or new transport is introduced.

Signing does not execute. Signing a revoke does not cancel an in-flight operation.
File storage still does not establish factual correctness or remove prompt injection.

## Why this is equivalent to the existing guarded path

The existing host CLI already restores retained state and submits its retained
document. The Python method exposes that route through the public facade. It calls
the same restore, lock, signature, expiry, spent-attempt and writer checks. No new
delivery path or state transition is added. This is a conditional code argument,
not a proof about arbitrary adapters, compromised hosts, rollback or power loss.

Direct facade tests exercise retained-byte changes, expiry, revoke, repeat, two
processes, child exits around BEGIN/permission/file/receipt, and recovery without
replay. See [verification](verification.md) for exact installed artifact checks.

## Compare honestly

From outside the checkout, after installing and verifying this exact source wheel:

```text
<harness-python> <checkout>/tools/measure_document_routes.py --out new-route-results --samples 16
```

This finite measurement uses fresh synthetic
tasks, one warmup per route and alternating route order. It compares the correct
compatibility callback (reads exact retained bytes, no model regeneration) with
host-only execution. Both must deliver identical bytes, preserve a protected neighbor,
reject repeat and verify readback. Output contains per-phase milliseconds and paired
submission p50/p95, not a pass/fail speed threshold.

The expected benefit is removing the post-review content argument and its caller-side
read/UTF-8/dispatch glue, **not a stronger permission guarantee or a required saved LLM
call**. The old route can also submit retained text without a model. Neither route
normalizes content or filters its meaning.

| Integration obligation | Compatibility callback | Host-only execution |
|---|---|---|
| Independent key enrollment, freeze, review, apply decision | Required | Required, unchanged |
| Post-review caller glue | Read retained bytes, UTF-8 decode, bind callback, dispatch exact text | Call `execute_approved()` |
| Document bytes in execution arguments | Full approved document | None; host restores retained document |
| Model calls required after approval | Zero | Zero |
| Current readback and conservative recovery | Required | Required, unchanged |

The shorter call does not remove operator review, enrollment or error handling.

`tests/test_native_parity.py` separately compares a configured native writer and a
test-only ordinary local approval reference with ActionGate. The ordinary reference
uses an assumed authenticated local operator callback, frozen bytes/target, durable
spent admission and the same writer. It is not a raw unguarded writer and is not a
claim about any vendor's approval product. Local callback authentication is assumed;
Action Authority's detached signature transport has additional enrollment/verification
obligations. Matching bounded outcomes are parity, not competitive superiority.
The ordinary reference's injected failure/readback checks are same-process checks;
they do not establish process-restart parity. The separate spawned-process crash
suite tests Action Authority, not the reference. Do not pool those evidence classes.

Human review time, human integration time and independent adoption remain unmeasured.
Repeated fixture timings are not independent attacks, statistical assurance or an
external user pilot. Private experiment outputs and raw model data stay outside Git.
