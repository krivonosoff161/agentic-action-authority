# Action Authority contributor contract

This repository owns exact-action approval, its public API and optional effect
adapters. Harness owns its existing file writer and the broader test laboratory.
Do not duplicate that writer here or claim arbitrary-tool containment.

Follow the operator's canonical global/Git contracts and resolve registered
checkouts when those facilities are present. Work on a scoped task branch;
preserve unknown changes. Product changes go through reviewed PRs and exact-head
checks. Merge, publication and access-policy changes require owner authority.

Keep real private keys, operator decisions, documents, runtime databases, raw
model output and local research outside Git. Tests use disposable fixtures only.
Retain Apache-2.0 attribution and upstream source provenance.

Core import must not require Harness or run I/O, network or a model. The optional
Harness adapter must preserve exact file binding, one spent attempt, revoke
ordering and recovery without delivery. An adapter is trusted host code, not
agent-supplied code or an OS sandbox. Do not weaken uncertainty into success.

Validate installed wheel bytes and run core and adapter checks on Windows and
Linux. Preserve failed attempts. Record revision, commands, results and limits;
assistant review is not independent human review. Keep live local SESSION/TASK
out of the public package. Public docs must distinguish shipped and planned work.

Delegate only bounded disjoint tasks, at most two helpers, no helper cascade.
