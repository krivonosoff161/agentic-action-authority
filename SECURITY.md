# Security boundary and reporting

Action Authority coordinates exact-action approvals in a trusted application.
The host, adapter code, state storage, enrolled public key and clock are trusted.
An agent receives only the narrow tool-call interface, not host configuration,
signing capability or direct access to the protected operation.

This is not an OS sandbox, semantic content checker, hidden-dependency detector,
coordinated-rollback defense or universal remote exactly-once mechanism. A signed
decision proves possession of the enrolled key, not sound human judgment.
Each adapter must document its effect, preconditions and recovery guarantees.
An uncertain result is not permission to retry.

Keep the operator key outside the agent environment. Same-user Python wrappers
and Windows file-mode flags do not establish account/process isolation.
Do not put credentials, real documents, approvals or runtime databases in issues.
Report reproducible synthetic failures in GitHub issues; for sensitive reports,
use GitHub private vulnerability reporting if the repository offers it, otherwise
ask the maintainer for a private channel without disclosing exploit or user data.

The initial0.x interface is experimental. Review and pin a tested release for a
pilot; a green CI run is not independent security certification.
