# Embed one reviewed document in a trusted host

This is the **0.2.0 `DocumentHost` API**. Confirm the exact 0.2.0 package is
available and install it using the [README](../README.md#start-with-one-document).
The required `--expected-key-fingerprint` / `--host-repository` setup flags
and `DocumentHost` are absent from the 0.1.1 wheel. Existing 0.1.1 task state
is not automatically migrated; see the [upgrade notes](upgrading-0.2.md).

For the **unreleased source checkout**, [host-only approved execution](approved-execution.md)
removes the content re-submission after review. It is not available in the
published 0.2.0 wheel. Preparation, independent enrollment and signing below
remain unchanged; only the final host execution call is simpler.

The host owns task state, public source admission, operator enrollment, review
transport and tool registration. The operator owns the private key and decision.
An agent receives only a content-only tool. This version supports one create-only
UTF-8 document through the installed Harness 1.14.2 guarded writer; it does not
call a model, provide a tool server, attest Git provenance, or isolate an agent
with unrestricted Python or filesystem access.

## Host preparation and operator review

Before running this host code, the operator independently supplies a public key
and its lowercase SHA-256 fingerprint through a trusted channel. The expected
fingerprint must not be calculated from the received key file merely to satisfy
enrollment. The host chooses a new task directory, an authorized public UTF-8
source, and the exact proposed document bytes. Replace the repository and SHA
with the host application's real owner/repository and revision. This pair is a
host declaration bound into the request, not remote provenance attestation.

```python
from pathlib import Path

from ash_action_authority import DocumentHost

# Trusted host configuration. Obtain this fingerprint independently from the operator.
expected_fingerprint = "REPLACE_WITH_SEPARATELY_VERIFIED_LOWERCASE_SHA256"
host = DocumentHost.prepare(
    Path("task-001"),
    public_key=Path("operator.hex"),
    expected_key_fingerprint=expected_fingerprint,
    source=Path("source.txt"),
    document=Path("proposed.txt"),
    host_repository="owner/host-application",
    host_revision="REPLACE_WITH_HOST_REPOSITORY_40_HEX_COMMIT",
    allow_local_source_use=True,
)
review = host.review_files  # {"request": Path, "content": Path}
# Transfer BOTH review files to the operator through the agreed trusted channel.
```

`prepare` refuses a mismatched key before creating task state. It does not
write the destination. Do not pass the host object, state directory, key file,
request signing, or decision application to the agent. Keep the review channel
and host configuration under application control.

The operator reviews the exact content and destination, then signs **outside
the agent environment** with the installed CLI. Key generation, if needed, is
an operator setup step in the [one-document guide](one-document.md); neither
this example nor the agent creates a key or approves automatically.

```text
<python> -m ash_action_authority.operator sign --private operator.pem --request task-001/request.json --content task-001/document.txt --decision approve --out approved.json
```

The operator enters the local passphrase and the full confirmation shown by
the CLI. Transport the detached decision back to the trusted host. Signing
does not write the document.

## Apply the decision and expose only the content tool

```python
from pathlib import Path

from ash_action_authority import DocumentHost

host = DocumentHost.open(Path("task-001"))
decision = host.apply_decision(Path("approved.json"))
if not decision.get("accepted"):
    raise RuntimeError("operator decision was not accepted")
descriptor = host.tool_descriptor()
dispatch = host.bind_tool()

# Register ONLY descriptor and dispatch with your agent framework, if any.
# For a provider-free exercise, call the same callback with the frozen text:
result = dispatch("submit_approved_document", {"content": Path("proposed.txt").read_bytes().decode("utf-8")})
readback = host.status(recover=True)
```

The callback accepts only the named tool and one `content` string. It rejects
path, approval and extra fields; changed content is refused. The host still
controls the destination and retains the state. Registering a callback is not
a sandbox if the agent can also write files or execute arbitrary host code.
Do not normalize line endings after review: `Path.read_text()` can translate
CRLF to LF on Windows, changing the approved bytes. Read bytes and decode UTF-8
as shown, then submit that exact text without rewriting it.
`status()` is historical; `status(recover=True)` performs readback or fencing
without delivery. Inspect the returned `outcome` and recovered state; do not
infer success from a submitted call alone.
The host can inspect `host.request()` for the current request; use
`host.export_request(new_path)` when a fresh review file is required, and
never overwrite an earlier review artifact.

## Refusal and recovery routes

| Observation | Host/operator next step |
|---|---|
| Key fingerprint mismatch or invalid host declaration | Stop setup. Verify the operator channel and the host's repository/revision; do not substitute a value to pass validation. |
| `not_approved` | Obtain an operator decision for the current exact request; no file effect has been admitted. |
| `object_changed` or changed retained input | Preserve the old task. Prepare a new task and obtain a new review for the changed document or source. |
| `expired` before BEGIN | Preserve the expired task. Prepare a new task with a new request, lifetime and operator review. |
| Revocation accepted before BEGIN | The prior challenge is invalid. Call `host.export_request(Path("next-request.json"))` to create a new review file and obtain a new decision. |
| Revocation reports `too_late_or_in_flight` | Treat the effect as possibly in flight; inspect `status(recover=True)` before deciding anything else. |
| `already_consumed`, `uncertain`, interruption or `UNKNOWN` | Reopen the original home, call `status(recover=True)`, inspect output and retained state. Never replay the old action or overwrite the target. |

Recovery may establish an exact receipt, reconcile an output, fence a verified
absence, or remain `UNKNOWN`. A fresh action after fencing needs a **new task
and new operator approval**. Keep partial state for investigation. An adapter
is trusted host code; the core cannot attest arbitrary custom effects.

If reopening or recovery itself refuses because retained input or host state
changed, stop and preserve the entire task for manual inspection. Do not edit
retained bytes to make recovery pass, recreate missing state, or infer that no
effect occurred. This API cannot automatically recover an integrity-broken
task; an operator must establish the outcome before authorizing any replacement.
