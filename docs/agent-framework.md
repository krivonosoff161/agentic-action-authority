# Agent Framework: one declaration, one reviewed document

The optional 0.4.0 adapter targets `agent-framework-core==1.23.0` and the
Harness 1.14.2 writer. It does not patch Microsoft's SDK or add a
general-purpose tool executor. It is absent from the 0.3.0 wheel. Check the
[0.4.0 index entry](https://pypi.org/project/agentic-action-authority/0.4.0/)
and [release evidence](https://github.com/krivonosoff161/agentic-action-authority/releases/tag/v0.4.0)
before relying on an index installation.

The useful boundary is small: the agent proposes a UTF-8 public document, the
application presents the exact retained action to an operator, and the existing
Harness writer creates that file only after a matching signed decision.

## Application integration

Register `declaration_only_document_tool()` from
`ash_action_authority.agent_framework` on an Agent. It returns a native
`FunctionTool(func=None)`: **content only**, no model-selected path, key, approval
or execution callback. A `WorkflowBuilder` workflow pauses with a `request_info`
event carrying the pending function call.

The trusted application handles that event:

```python
from ash_action_authority.agent_framework import AgentFrameworkDocument

pending = paused.get_request_info_events()
if len(pending) != 1:
    raise ValueError("This host accepts exactly one pending document")
event = pending[0]

adapter = AgentFrameworkDocument.prepare(
    new_task_home, event,
    workflow_id=host_workflow_id,
    public_key=enrolled_public_key_file,
    expected_key_fingerprint=independently_confirmed_fingerprint,
    host_repository="example/my-application",
    host_revision=exact_host_revision,
    allow_local_source_use=True,  # host declares this proposal PUBLIC
)
# Send BOTH files over your trusted operator channel, not through the model:
review = adapter.host.review_files  # request + exact retained document
# The operator reviews and signs using the existing operator CLI.
adapter.host.apply_decision(detached_operator_decision)

# The same pending occurrence must always route to this same retained home.
adapter = AgentFrameworkDocument.open(new_task_home)
responses = adapter.execute(event, workflow_id=host_workflow_id)
continued = await workflow.run(responses=responses)
```

Use the existing [operator instructions](one-document.md) for enrollment, review,
signing and decision transfer. `apply_decision` is not approval by itself: it
verifies the operator's detached signature. Neither the adapter nor an agent has
a signing key. Do not derive the expected fingerprint from an untrusted key file.

Paths, workflow identity, repository/revision declarations and consent to local
public-data processing are host configuration. They must not come from model
arguments. The output remains `<task-home>/output/document.md`, create-only.
This is the existing supported file effect, not arbitrary Agent Framework tools.

## What is bound, and when

The adapter accepts a native pending declaration for `write_reviewed_document`.
Arguments must be a JSON object with exactly one string `content`. Duplicate JSON
keys, constants such as NaN, extra fields, empty/oversized content, invalid UTF-8,
and non-pending events are rejected before task preparation. JSON formatting may
vary; the decoded document's UTF-8 bytes are never normalized (including CRLF).

The retained source record binds the host workflow ID, framework request ID,
executor ID, call ID, tool name, and exact content hash. Its digest becomes the
existing signed `declared-source` dependency; the document hash/length and exact
file destination are also covered by the existing approval request. The source
here is the **captured proposal identity**, not proof of the document's upstream
data provenance, truth, or freedom from injection.

Before execution, the pending event and workflow identity must match this retained
record. A mismatch raises `AuthorityError("framework_call_changed")` without
spending approval or writing the output. After a match, execution uses the
existing `DocumentHost.execute_approved()` and its retained document, not a new
model response. The normal expired/revoked/spent checks remain in that coordinator.

The native SDK does not run validation or FunctionMiddleware for declaration-only
tools. This bridge performs its own narrow input validation. It does **not** claim
automatic FIDES label tracking or policy enforcement on this route. Native tool
approval and an Action Authority signed decision are separate mechanisms.

## Lost response and recovery

File execution and returning a result to the workflow are separate operations.
If `workflow.run(responses=...)` fails after writing, do not create another task
or ask the agent to regenerate the document. Preserve the original task home and
pending occurrence. The repeated `execute` call cannot grant a second attempt.

```python
adapter = AgentFrameworkDocument.open(existing_task_home)
responses = adapter.recover_response(original_pending_event, workflow_id=host_workflow_id)
# Inspect the outcome before deciding whether to resume your workflow.
# Recovery never calls the writer's delivery method.
```

Only a currently verified `DELIVERED_RECEIPT` or `RECONCILED_POSTCONDITION` produces
`applied / verified_existing_effect` with `recovered: true`. Otherwise the response
is `uncertain / host_recovery_required`, or corrupt routing state refuses reopening.
That result is not new permission. Never silently report an uncertain action as
success, and do not automatically retry it. Native `Content.result` serializes
the result mapping as JSON text.

The adapter does not persist the Agent Framework workflow, authenticate routing
identities, manage a cross-task deduplication registry, or provide exactly-once
result delivery. The host owns its workflow/checkpoint storage and maps one
occurrence to one task home. An operator can approve a distinct new task; this
component does not make two approvals globally identical. Trusted-host/filesystem
and local recovery limits from [architecture](architecture.md) still apply.

## Reproduce without a model or credentials

Use Python 3.11 and a fresh virtual environment. After confirming the index
and release evidence, install the optional extra:

```console
python -m pip install "agentic-action-authority[agent-framework]==0.4.0"
python -m pip check
```

To reproduce from an exact checkout, activate a fresh environment, then build
and install that checkout's wheel:

```console
python -m pip --isolated install --index-url https://pypi.org/simple --require-hashes -r requirements/build.txt
python -m build --no-isolation --wheel --outdir dist
python -m pip --isolated install "./dist/agentic_action_authority-0.4.0-py3-none-any.whl[agent-framework]"
python examples/agent_framework_document.py
```

CI additionally installs the platform dependency locks and
`requirements/agent-framework.txt` with hash verification.
The example uses the real native Agent/Workflow/function-invocation layer and a
scripted in-memory chat client. Its fixed test signer is explicitly **synthetic**;
it is not an operator-review implementation and must not be used in production.
It creates and cleans disposable files only, with zero model/provider calls.
The example discards the first workflow after writing, opens a new workflow from
the native on-disk checkpoint, and resumes with verified readback of that same
effect. It does not call the writer again.

The optional installed test lane uses the same native SDK and separate signature,
substitution, replay and recovery controls. Other installed core/Harness lanes
remain independent of the framework dependency. Passing these controls establishes
the tested file integration, not model safety, independent human review, or
Microsoft adoption.

## Provenance and contribution status

The integration follows the public declaration-only route described in
[Agent Framework discussion #9667](https://github.com/microsoft/agent-framework/discussions/9667#discussioncomment-19163202)
and the [native workflow sample at commit 67ba500e](https://github.com/microsoft/agent-framework/blob/67ba500ec1fd312606a5d585a42335cd8631e851/python/samples/03-workflows/human-in-the-loop/agents_with_declaration_only_tools.py).
The correspondent's reported tests are not our test results or maintainer approval.
Our example is an independently authored offline test, not a copy of the Azure
sample or a requirement for Azure credentials. The SDK dependency retains its own
MIT licensing; Action Authority remains Apache-2.0.

Microsoft's contribution policy requires agreement before a nontrivial upstream
implementation/PR. This is an optional integration in Action Authority; any
upstream proposal is separate, subject to that agreement and AI-assistance
disclosure. No upstream acceptance or endorsement is claimed.
