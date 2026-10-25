"""Optional host-owned bridge from a native pending call to one retained document.

The framework tool has no executable function. This object, its paths, workflow
identity and approval methods belong to the trusted application, never the model.
It does not modify Agent Framework's approval loop or execute arbitrary tools.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from agent_framework import Content, FunctionTool, WorkflowEvent

from .core import AuthorityError
from .document import DocumentHost
from .operator import _read_bounded, _reject_constant, _unique_json
from .protocol import canonical

TOOL_NAME = "write_reviewed_document"
_SCHEMA = "action-authority-agent-framework-document-v1"
_MAX_CONTENT = 65536
_FIELDS = frozenset({
    "schema", "workflow_id", "request_id", "source_executor_id", "call_id",
    "tool_name", "content_sha256",
})


def declaration_only_document_tool() -> FunctionTool:
    """Declare content-only input; native execution/approval grants no AA authority."""
    return FunctionTool(
        name=TOOL_NAME,
        description="Propose a public document for separate operator review and host execution.",
        func=None,
        input_model={
            "type": "object",
            "properties": {"content": {"type": "string"}},
            "required": ["content"],
            "additionalProperties": False,
        },
    )


def _identity(value: object) -> str:
    # Routing identifiers are opaque, not paths, approvals or identity authentication.
    if (type(value) is not str or not 1 <= len(value) <= 256
            or any(ord(c) < 32 or ord(c) > 126 for c in value)):
        raise AuthorityError("invalid_framework_identity")
    return value


def _capture(event: WorkflowEvent, workflow_id: str) -> tuple[dict[str, str], bytes]:
    if not isinstance(event, WorkflowEvent) or event.type != "request_info":
        raise AuthorityError("pending_declaration_required")
    data = event.data
    if (not isinstance(data, Content) or data.type != "function_call"
            or data.user_input_request is not True or data.name != TOOL_NAME):
        raise AuthorityError("pending_declaration_required")
    try:
        arguments = data.arguments
        if type(arguments) is str:
            if len(arguments) > _MAX_CONTENT * 6 + 1024:
                raise AuthorityError("invalid_framework_arguments")
            arguments = json.loads(
                arguments, object_pairs_hook=_unique_json, parse_constant=_reject_constant,
            )
        if (type(arguments) is not dict or set(arguments) != {"content"}
                or type(arguments["content"]) is not str):
            raise AuthorityError("invalid_framework_arguments")
        content = arguments["content"].encode("utf-8")
        if not 1 <= len(content) <= _MAX_CONTENT:
            raise AuthorityError("invalid_framework_arguments")
        record = {
            "schema": _SCHEMA,
            "workflow_id": _identity(workflow_id),
            "request_id": _identity(event.request_id),
            "source_executor_id": _identity(event.source_executor_id),
            "call_id": _identity(data.call_id),
            "tool_name": TOOL_NAME,
            "content_sha256": hashlib.sha256(content).hexdigest(),
        }
    except AuthorityError:
        raise
    except Exception as exc:
        # Do not leak raw model input or parser errors through a tool response.
        raise AuthorityError("invalid_framework_arguments") from exc
    return record, content


@dataclass(frozen=True)
class AgentFrameworkDocument:
    """One host-selected home for one workflow occurrence and one approved effect.

    The host must route the same occurrence to the same retained home. Identifiers
    are bound review data, not proof of a workflow's authenticity. A new home needs
    a new approval; this is not a global deduplication service or workflow store.
    """

    home: Path

    @classmethod
    def prepare(
        cls,
        home: Path,
        event: WorkflowEvent,
        *,
        workflow_id: str,
        public_key: Path,
        expected_key_fingerprint: str,
        host_repository: str,
        host_revision: str,
        valid_seconds: int = 3600,
        allow_local_source_use: bool = False,
    ) -> AgentFrameworkDocument:
        """Capture exact bytes and pending-call identity, without approving or executing.

        All parameters except event are host configuration. Only public proposal
        content is supported. Enrollment must be independent of model output.
        Incomplete tasks are preserved on failure; do not resume by preparing again.
        """
        record, content = _capture(event, workflow_id)
        home = home.absolute()
        if home.exists() or home.is_symlink():
            raise AuthorityError("home_exists_use_new_directory")
        if allow_local_source_use is not True:
            raise AuthorityError("host_must_authorize_local_public_source_use")
        # DocumentHost copies both inputs into its retained, digest-bound state.
        # The temporary inputs are never an alternate execution/approval channel.
        with TemporaryDirectory(prefix="authority-declaration-", dir=home.parent) as temporary:
            inputs = Path(temporary)
            source = inputs / "declaration.json"
            document = inputs / "document.txt"
            source.write_bytes(canonical(record))
            document.write_bytes(content)
            DocumentHost.prepare(
                home,
                public_key=public_key,
                expected_key_fingerprint=expected_key_fingerprint,
                source=source,
                document=document,
                host_repository=host_repository,
                host_revision=host_revision,
                valid_seconds=valid_seconds,
                allow_local_source_use=allow_local_source_use,
            )
        return cls(home)

    @classmethod
    def open(cls, home: Path) -> AgentFrameworkDocument:
        """Reopen captured state, never recreate missing state or replay an effect."""
        adapter = cls(home.absolute())
        _ = adapter.binding
        return adapter

    @property
    def host(self) -> DocumentHost:
        """Host-only review, decision and status API; do not register as a model tool."""
        return DocumentHost.open(self.home)

    @property
    def binding(self) -> dict[str, str]:
        """Detached routing data covered by the signed declared-source dependency."""
        # Restore verifies source bytes, original binding, content and local state.
        _ = self.host
        try:
            record = json.loads(
                _read_bounded(self.home / "source.txt", 65536).decode("utf-8"),
                object_pairs_hook=_unique_json, parse_constant=_reject_constant,
            )
            if (type(record) is not dict or set(record) != _FIELDS
                    or record["schema"] != _SCHEMA or record["tool_name"] != TOOL_NAME):
                raise ValueError("invalid_record")
            for field in ("workflow_id", "request_id", "source_executor_id", "call_id"):
                _identity(record[field])
            content = _read_bounded(self.home / "document.txt", _MAX_CONTENT)
            if record["content_sha256"] != hashlib.sha256(content).hexdigest():
                raise ValueError("invalid_content_binding")
            return record
        except Exception as exc:
            raise AuthorityError("invalid_framework_binding") from exc

    def _match(self, event: WorkflowEvent, workflow_id: str) -> dict[str, str]:
        try:
            record, _ = _capture(event, workflow_id)
        except AuthorityError as exc:
            raise AuthorityError("framework_call_changed") from exc
        if record != self.binding:
            raise AuthorityError("framework_call_changed")
        return record

    @staticmethod
    def _response(record: dict[str, str], result: dict[str, Any]) -> dict[str, Content]:
        return {
            record["request_id"]: Content.from_function_result(
                call_id=record["call_id"], result=result,
            ),
        }

    def execute(self, event: WorkflowEvent, *, workflow_id: str) -> dict[str, Content]:
        """Verify the occurrence, then attempt the retained action once through AA.

        Return data for workflow.run(responses=...). This method does not resume
        the workflow, acknowledge response delivery, sign, retry or call a model.
        After a lost response use recover_response, not another execution attempt.
        """
        record = self._match(event, workflow_id)
        result = self.host.execute_approved()
        return self._response(record, result)

    def recover_response(
        self, event: WorkflowEvent, *, workflow_id: str,
    ) -> dict[str, Content]:
        """Read back an existing effect without delivery; uncertainty stays explicit.

        A verified existing effect can be reported again to the original pending
        occurrence. This is not an exactly-once guarantee for workflow responses.
        """
        record = self._match(event, workflow_id)
        result: dict[str, Any] = {"outcome": "uncertain", "reason": "host_recovery_required"}
        try:
            status = self.host.status(recover=True)
            if (status.get("current_verified") is True
                    and status.get("state") in {"DELIVERED_RECEIPT", "RECONCILED_POSTCONDITION"}):
                result = {"outcome": "applied", "reason": "verified_existing_effect", "recovered": True}
        except Exception:
            pass
        return self._response(record, result)
