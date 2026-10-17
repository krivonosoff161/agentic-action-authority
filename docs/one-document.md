# One document, one approval, one attempt

Use the installed environment from the README. Host and operator are separate
roles, even if exercised manually on one machine. Use only public source material
you are authorized to reuse. The host does not generate text or call a model:
supply the already-proposed UTF-8 document.

## 1. Operator: create and enroll a key

Run outside the agent environment, choosing a NEW private file in an
operator-controlled folder/device:

```text
<python> -m ash_action_authority.operator keygen --private operator.pem --public operator.hex
```

Enter the passphrase twice locally. Share only the public file and fingerprint.
The host independently enrolls the expected key; an agent-supplied public file
is not enrollment. File mode 0600 alone is not Windows isolation. Use a separate
account/device and appropriate permissions. Preserve existing keys and failed
setup evidence; do not overwrite them to force a retry.

## 2. Host: prepare the exact action

Choose a NEW task directory. Replace HOST_CODE_COMMIT_SHA with the actual trusted
host revision. source.txt is public source material; proposed.txt is the exact
proposed document, not instructions to execute.

```text
<python> -m ash_action_authority.host setup --home new-task --public-key operator.hex --source source.txt --document proposed.txt --host-revision HOST_CODE_COMMIT_SHA --allow-local-source-use
```

No destination write occurs here. The only destination is
`new-task/output/document.md`; the model cannot select its path.
The source-use flag authorizes this local source contract, not network access.
The default request lifetime is 3,600 seconds (maximum 86,400).
Source capture is local/unattested and does not discover hidden dependencies.

## 3. Operator: review and sign

Receive BOTH request.json and document.txt through a trusted review channel:

```text
<python> -m ash_action_authority.operator sign --private operator.pem --request new-task/request.json --content new-task/document.txt --decision approve --out approved.json
```

Inspect escaped exact content and destination. Type the full confirmation shown
by the program with its ACTUAL digest prefix, not an ellipsis. Enter the passphrase
locally. There is no unattended --yes bypass. The detached decision is not the
private key. Signing alone does not execute anything.

## 4. Host: apply, execute, read back

```text
<python> -m ash_action_authority.host apply-decision --home new-task --decision approved.json
<python> -m ash_action_authority.host run --home new-task
<python> -m ash_action_authority.host status --home new-task --recover
```

Success creates the file once, then verifies exact bytes. A second run is refused.
Status without --recover is historical, not current readback. CLI exit 0 means
command success, 1 refusal, 2 uncertainty/busy coordination. A failed command does
not establish that no effect happened.

## Revoke and recover

Before BEGIN, sign the current request with --decision revoke and apply it.
An accepted revocation changes the challenge, invalidating old approval.
Export a fresh request to a NEW file before subsequent review:

```text
<python> -m ash_action_authority.host request --home new-task --out next-request.json
```

BEGIN is the durable EXECUTING commit, before physical I/O. A revocation that
loses this race says too_late_or_in_flight, not cancelled. Expiry limits admission,
not completion of an already-started write.

After interruption use status --recover. Recovery does not deliver again:

| State | Meaning |
|---|---|
| DELIVERED_RECEIPT | Supported exact output and retained writer receipt observed. |
| RECONCILED_POSTCONDITION | Exact output after ambiguity; not proof of original return. |
| FENCED_ABSENT | Old attempt disabled and target absence observed. |
| UNKNOWN | Stop and inspect. Do not retry or overwrite. |

Historical success is separate from current readback. A new action after fencing
needs a new task and new approval. Preserve partial directories for investigation.
