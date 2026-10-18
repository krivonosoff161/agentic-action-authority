# One document, one approval, one attempt

This guide uses the **0.2.0 onboarding API**. Confirm the exact 0.2.0 package
is available and install it using the [README route](../README.md#start-with-one-document).
Version 0.1.1 does not have `DocumentHost` or the required fingerprint and
host-repository setup flags. Existing 0.1.1 tasks are not automatically migrated;
see the [upgrade notes](upgrading-0.2.md). Host and operator are separate
roles, even if exercised manually on one machine. Use only public source material
you are authorized to reuse. The host does not generate text or call a model:
supply the already-proposed UTF-8 document.

## 1. Operator: create and enroll a key

Run outside the agent environment, choosing a NEW private file in an
operator-controlled folder/device:

```text
<python> -m ash_action_authority.operator keygen --private operator.pem --public operator.hex
```

Enter the passphrase twice locally. Share only the public file and its SHA-256
fingerprint. The host obtains the expected fingerprint through an **independent
trusted operator channel** and compares it with the supplied public key before
creating task state. Do not derive the expected value from that same key file or
accept an agent-supplied value as enrollment. File mode 0600 alone is not Windows isolation. Use a separate
account/device and appropriate permissions. Preserve existing keys and failed
setup evidence; do not overwrite them to force a retry.

## 2. Host: prepare the exact action

Choose a NEW task directory. Replace `OWNER/HOST_REPOSITORY` and
`HOST_CODE_COMMIT_SHA` with the trusted host application's owner/repository and
the exact revision of that repository. Both are host declarations; the library
checks their shape and binds them, but does not attest remote Git provenance.
Replace `EXPECTED_OPERATOR_KEY_FINGERPRINT` with the lowercase 64-character
fingerprint received independently from the operator. `source.txt` is public source material; `proposed.txt` is the exact
proposed document, not instructions to execute.

```text
<python> -m ash_action_authority.host setup --home new-task --public-key operator.hex --expected-key-fingerprint EXPECTED_OPERATOR_KEY_FINGERPRINT --source source.txt --document proposed.txt --host-repository OWNER/HOST_REPOSITORY --host-revision HOST_CODE_COMMIT_SHA --allow-local-source-use
```

No destination write occurs here. The only destination is
`new-task/output/document.md`; the model cannot select its path.
The source-use flag authorizes this local source contract, not network access.
The default request lifetime is 3,600 seconds (maximum 86,400).
Source capture is local/unattested and does not discover hidden dependencies.
An enrollment mismatch refuses before creating the task; investigate the
trusted channel rather than replacing the expected fingerprint to make it pass.

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
Export a fresh request to a NEW file before subsequent review and obtain a
new signed decision:

```text
<python> -m ash_action_authority.host request --home new-task --out next-request.json
```

BEGIN is the durable EXECUTING commit, before physical I/O. A revocation that
loses this race says too_late_or_in_flight, not cancelled. Expiry limits admission,
not completion of an already-started write.

If the request expires before BEGIN, preserve the expired task and create a
**new task with a new request and review**. Do not extend its deadline, reuse its
approval, or submit again. If a document or source changes, also use a new task
and review; editing retained task files is not a recovery method.

After interruption use status --recover. Recovery does not deliver again:

| State | Meaning |
|---|---|
| DELIVERED_RECEIPT | Supported exact output and retained writer receipt observed. |
| RECONCILED_POSTCONDITION | Exact output after ambiguity; not proof of original return. |
| FENCED_ABSENT | Old attempt disabled and target absence observed. |
| UNKNOWN | Stop and inspect. Do not retry or overwrite. |

Historical success is separate from current readback. A new action after fencing
needs a new task and new approval. Preserve partial directories for investigation.
