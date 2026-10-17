"""Optional Harness-backed create-only file effect adapter."""

from __future__ import annotations

from pathlib import Path

from agentic_security_harness.workspace_admission import WorkspaceAdmission
from agentic_security_harness.workspace_operation import WorkspaceOperation
from agentic_security_harness.workspace_writer import WorkspacePolicy

from .core import ActionCore, AuthorityError, _directory, _sha
from .core import AuthorityBusy as AuthorityBusy


class _HarnessFileEffect:
    def __init__(self, root, workspace, *, content, operation_id, artifact,
                 public_key, app_id, task_id, initiator, expires_at,
                 dependencies, admission):
        if (type(workspace) is not WorkspacePolicy
                or (admission is not None and type(admission) is not WorkspaceAdmission)):
            raise AuthorityError("invalid_host_configuration")
        workspace.check()
        if (root == workspace.output_dir or workspace.output_dir in root.parents
                or root in workspace.output_dir.parents):
            raise AuthorityError("state_and_output_must_be_disjoint")
        if artifact not in dict(workspace.outputs):
            raise AuthorityError("unknown_host_artifact")
        if (workspace.source_expires_at is not None
                and expires_at > workspace.source_expires_at.timestamp()):
            raise AuthorityError("approval_exceeds_source_lifetime")
        raw = content.encode("utf-8")
        info = workspace.output_dir.stat()
        self.binding = {
            "app_id": app_id, "task_id": task_id, "operation_id": operation_id,
            "initiator": initiator, "action": "write_text", "artifact": artifact,
            "policy_sha256": workspace.sha256,
            "source_admission_sha256": admission.binding_sha256 if admission is not None else None,
            "root_path": str(workspace.output_dir), "root_device": str(info.st_dev),
            "root_inode": str(info.st_ino), "filename": dict(workspace.outputs)[artifact],
            "payload_sha256": _sha(raw), "payload_length": len(raw),
            "dependencies": dict(dependencies or {}),
            "operator_key_fingerprint": _sha(public_key),
        }
        self.workspace, self.content, self.operation_id = workspace, content, operation_id
        self.artifact, self.admission = artifact, admission
        self.max_bytes = workspace.max_bytes

    def check(self):
        self.workspace.check()

    def create(self, state_path):
        WorkspaceOperation.create(state_path, self.workspace,
                                  operation_id=self.operation_id, artifact=self.artifact,
                                  content=self.content, max_attempts=1, admission=self.admission)

    def open(self, state_path):
        return WorkspaceOperation.open(state_path, self.workspace,
                                       operation_id=self.operation_id, artifact=self.artifact,
                                       content=self.content, max_attempts=1,
                                       admission=self.admission)

    def target_absent(self):
        self.workspace.check()
        _directory(self.workspace.output_dir)
        info = self.workspace.output_dir.stat()
        if (str(info.st_dev) != self.binding["root_device"]
                or str(info.st_ino) != self.binding["root_inode"]):
            raise AuthorityError("workspace_identity_changed")
        try:
            (self.workspace.output_dir / self.binding["filename"]).lstat()
        except FileNotFoundError:
            return True
        return False


class ActionGate(ActionCore):
    """Compatibility API for the existing Harness file operation."""

    def __init__(self, root: Path, workspace: WorkspacePolicy, *, content,
                 operation_id, artifact, public_key, key_id, app_id, task_id,
                 initiator, expires_at, dependencies=None, admission=None, clock=None):
        effect = _HarnessFileEffect(
            root, workspace, content=content, operation_id=operation_id,
            artifact=artifact, public_key=public_key, app_id=app_id,
            task_id=task_id, initiator=initiator, expires_at=expires_at,
            dependencies=dependencies, admission=admission)
        super().__init__(root, effect, content=content, public_key=public_key,
                         key_id=key_id, app_id=app_id, task_id=task_id,
                         initiator=initiator, expires_at=expires_at, clock=clock)
        self.workspace, self.operation_id = workspace, operation_id
        self.artifact, self.admission = artifact, admission
