# Choose an approval path for one document

This is a **contract comparison**, based on the linked primary documentation
read on 2026-10-18 and this repository's 0.2.0 API. It is not a run of
Pydantic AI, LangChain or GitHub against the same fixture, a performance result,
or an external user pilot. Confirm 0.2.0 package availability before using
`DocumentHost`; the 0.1.1 wheel does not contain it.

| Path | Documented approval route | What the application must establish for an exact create-only document |
|---|---|---|
| [Pydantic AI deferred tools](https://pydantic.dev/docs/ai/tools-toolsets/deferred-tools/) | A tool can require approval. Deferred results identify pending tool calls and can approve, deny, or approve with `override_args`; calls can resume in a later run. Pydantic also documents [durable execution integrations](https://pydantic.dev/docs/ai/capabilities/durable_execution/overview/). | Authenticate the client/approval endpoint, bind the final arguments and destination that will execute, and establish effect idempotency and readback for the selected host and durable engine. Pydantic explicitly separates HITL approval from authorization of untrusted clients. |
| [LangChain HITL](https://docs.langchain.com/oss/python/langchain/human-in-the-loop) | Middleware interrupts selected tool calls for `approve`, `edit`, `reject`, or `respond`; persisted graph state supports pause and resume. Production use calls for a persistent checkpointer. | Decide whether edits become a newly reviewed action, then bind the final arguments at the actual effect. Test retries, repeated resumes and uncertain writes with the chosen tool and storage implementation. The documented middleware already offers real approval controls; it is not an `if approved: execute` toy. |
| [GitHub protected branch and PR review](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches) | Required reviews and status checks can gate a protected-branch merge. When configured, stale-approval dismissal requires another review after a change to the approved diff. | If the document's final effect is the reviewed repository change, this may be the right boundary. If a separate application writes a file outside that merge, establish how the reviewed commit binds to that effect and how retries and uncertain writes are handled. Check actual repository rules; stale-approval dismissal is optional. |
| Action Authority 0.2.0 `DocumentHost` | A trusted host prepares exact content/destination, independently enrolls the operator key, applies a detached signed decision and exposes a content-only callback. One attempt is spent at BEGIN; `status(recover=True)` reads back or fences without delivery. | Integrate a trusted host, separate review channel and operator CLI; keep the agent away from unrestricted host access; use the supported local filesystem and Harness writer. The dependency, operator workflow and retained state add work. `UNKNOWN` still needs investigation and never permits replay. |

For a document already governed completely by a protected PR, adding a second
approval flow may be unnecessary. For an application already using deferred/HITL
calls plus a trusted callback and durable effect handling, compare the actual
code and operator steps before adding another dependency. This package is most
relevant when the application needs its specific exact-document binding,
independent signature, one-attempt record and local file recovery outside a
Git merge. This is a choice criterion, **not** a claim that other paths fail or
that Action Authority is faster or safer in general.

The [bounded developer exercise](user-pilot.md) proposes equal fixtures and
records integration time, help requests, wrong assumptions and recovery
results. No such comparative measurements or human adoption results are
reported here. No option proves document truth or isolates a compromised host.
