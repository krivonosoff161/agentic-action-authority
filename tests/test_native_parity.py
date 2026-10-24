"""Offline native-writer and local approval parity; no human consent is inferred.

The test-only local approval reference assumes an authenticated operator callback
outside the agent environment. It does not secure transport or offer a product API.
Both sides use the same Harness WorkspaceOperation and disposable files.
"""

from __future__ import annotations

import hashlib
import sqlite3
import time
import unittest
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from agentic_security_harness.workspace_operation import WorkspaceOperation, WorkspaceOperationError
from agentic_security_harness.workspace_writer import WorkspacePolicy
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ash_action_authority.core import ActionCore
from ash_action_authority.engine import ActionGate
from ash_action_authority.protocol import canonical, decision_message


class _LocalApprovalReference:
    """Test-only trusted-host approval around one Harness operation.

    The host freezes content and destination at construction. An authenticated
    local operator calls approve/revoke; agents may only call submit(content).
    SQLite claims one attempt before effect I/O, and recovery only fences.
    """

    def __init__(self, operation, state_path: Path, content: str, expires_at: int, clock):
        self.operation = operation
        self.state_path = state_path
        self.digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        self.expires_at = expires_at
        self.clock = clock
        with closing(sqlite3.connect(state_path)) as db:
            db.execute("CREATE TABLE approval (state TEXT NOT NULL)")
            db.execute("INSERT INTO approval VALUES ('PENDING')")
            db.commit()

    def _transition(self, allowed: tuple[str, ...], new_state: str) -> bool:
        with closing(sqlite3.connect(self.state_path)) as db:
            db.execute("BEGIN IMMEDIATE")
            state = db.execute("SELECT state FROM approval").fetchone()[0]
            if state not in allowed:
                db.rollback()
                return False
            db.execute("UPDATE approval SET state = ?", (new_state,))
            db.commit()
            return True

    def approve(self) -> bool:
        return self.clock() < self.expires_at and self._transition(("PENDING",), "APPROVED")

    def revoke(self) -> bool:
        return self._transition(("PENDING", "APPROVED"), "REVOKED")

    def _record_outcome(self, state: str) -> None:
        self._transition(("EXECUTING",), state)

    def submit(self, content: str) -> dict:
        try:
            raw = content.encode("utf-8") if type(content) is str else b""
        except UnicodeError:
            raw = b""
        if not raw or hashlib.sha256(raw).hexdigest() != self.digest:
            return {"applied": False, "reason": "object_changed"}
        with closing(sqlite3.connect(self.state_path)) as db:
            db.execute("BEGIN IMMEDIATE")
            state = db.execute("SELECT state FROM approval").fetchone()[0]
            if state in ("EXECUTING", "UNKNOWN", "DELIVERED_RECEIPT"):
                reason = "already_consumed"
            elif state != "APPROVED":
                reason = "not_approved"
            elif self.clock() >= self.expires_at:
                reason = "expired"
            else:
                reason = None
                db.execute("UPDATE approval SET state = 'EXECUTING'")
            db.commit()
        if reason:
            return {"applied": False, "reason": reason}
        try:
            permission = self.operation.authorize()
            result = self.operation.deliver(permission)
            state = result["state"]
        except (OSError, sqlite3.Error, WorkspaceOperationError):
            state = "UNKNOWN"
        try:
            self._record_outcome(state)
        except (OSError, sqlite3.Error):
            return {"applied": False, "reason": "uncertain"}
        return {"applied": state == "DELIVERED_RECEIPT", "reason": state}

    def recover(self) -> dict:
        """Read back or fence the spent operation; never call deliver."""
        return self.operation.fence()


class NativeParityTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = TemporaryDirectory(prefix="ash-native-parity-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.content = "Exact public parity document.\n"
        self.now = int(time.time())
        self.signer = Ed25519PrivateKey.generate()
        self.public_key = self.signer.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def pair(self, name: str, *, approve: bool = True):
        operation_id = hashlib.sha256(f"{name}:one-action".encode()).hexdigest()
        sides = {}
        for side in ("native", "candidate"):
            home = self.base / name / side
            output = home / "output"
            state = home / "state"
            output.mkdir(parents=True)
            state.mkdir()
            policy = WorkspacePolicy(
                output_dir=output,
                outputs=(("report", "report.md"),),
                max_bytes=65536,
                max_proposals=8,
                data_class="public",
            )
            policy.check()
            sides[side] = (output, state, policy)
        native_output, native_state, native_policy = sides["native"]
        candidate_output, candidate_state, candidate_policy = sides["candidate"]
        native = WorkspaceOperation.create(
            native_state / "operation.sqlite",
            native_policy,
            operation_id=operation_id,
            artifact="report",
            content=self.content,
            max_attempts=1,
        )
        candidate = ActionGate.create(
            candidate_state / "authority",
            candidate_policy,
            content=self.content,
            operation_id=operation_id,
            artifact="report",
            public_key=self.public_key,
            key_id="fixture-operator-key",
            app_id="fixture-app",
            task_id=name,
            initiator="fixture-agent",
            expires_at=self.now + 3600,
            clock=lambda: self.now,
        )
        if approve:
            self.decide(candidate, "approve")
        return native, candidate, native_output, candidate_output

    def decide(self, candidate: ActionGate, decision: str) -> dict:
        message = decision_message(candidate.request(), decision=decision, issued_at=self.now)
        result = candidate.apply_decision(message, self.signer.sign(canonical(message)))
        self.assertTrue(result["accepted"])
        return result

    def approval_pair(self, name: str):
        native, candidate, native_output, candidate_output = self.pair(name, approve=False)
        reference = _LocalApprovalReference(
            native,
            native_output.parent / "state" / "approval.sqlite",
            self.content,
            self.now + 3600,
            lambda: self.now,
        )
        return reference, candidate, native_output, candidate_output

    @staticmethod
    def receipts(output: Path) -> tuple[Path, ...]:
        return tuple(sorted(output.glob(".ash-*-result.json")))

    def assert_exact_outputs(self, native_output: Path, candidate_output: Path) -> None:
        for output in (native_output, candidate_output):
            self.assertEqual((output / "report.md").read_bytes(), self.content.encode())
            self.assertEqual(len(self.receipts(output)), 1)

    def test_legal_exact_document_write_succeeds_on_both(self) -> None:
        native, candidate, native_output, candidate_output = self.pair("legal")
        permission = native.authorize()
        native_result = native.deliver(permission)
        candidate_result = candidate.submit(self.content)
        self.assertEqual(native_result["state"], "DELIVERED_RECEIPT")
        self.assertEqual(native_result["attempts_spent"], 1)
        self.assertTrue(candidate_result["applied"])
        self.assertEqual(candidate_result["status"], "DELIVERED_RECEIPT")
        self.assert_exact_outputs(native_output, candidate_output)
        self.assertEqual(native.fence()["reason"], "verified_retained_outcome")
        self.assertTrue(candidate.recover()["current_verified"])

    def test_foreign_target_before_delivery_is_not_overwritten_on_either(self) -> None:
        native, candidate, native_output, candidate_output = self.pair("foreign")
        permission = native.authorize()
        foreign = b"foreign pre-existing bytes"
        for output in (native_output, candidate_output):
            (output / "report.md").write_bytes(foreign)
        native_result = native.deliver(permission)
        candidate_result = candidate.submit(self.content)
        self.assertEqual(native_result["state"], "UNKNOWN")
        self.assertEqual(candidate_result["status"], "UNKNOWN")
        self.assertFalse(candidate_result["applied"])
        for output in (native_output, candidate_output):
            self.assertEqual((output / "report.md").read_bytes(), foreign)
            self.assertEqual(self.receipts(output), ())

    def test_duplicate_native_permission_and_candidate_submit_cause_one_effect(self) -> None:
        native, candidate, native_output, candidate_output = self.pair("duplicate")
        permission = native.authorize()
        self.assertEqual(native.deliver(permission)["state"], "DELIVERED_RECEIPT")
        self.assertTrue(candidate.submit(self.content)["applied"])
        before = {
            output: (
                (output / "report.md").stat().st_ino,
                (output / "report.md").stat().st_mtime_ns,
                tuple(
                    (path.name, path.stat().st_ino, path.stat().st_mtime_ns)
                    for path in self.receipts(output)
                ),
            )
            for output in (native_output, candidate_output)
        }
        repeated = native.deliver(permission)
        denied = candidate.submit(self.content)
        self.assertEqual(repeated["state"], "DELIVERED_RECEIPT")
        self.assertEqual(repeated["reason"], "verified_retained_outcome")
        self.assertEqual(repeated["attempts_spent"], 1)
        self.assertFalse(denied["applied"])
        self.assertEqual(denied["reason"], "already_consumed")
        self.assert_exact_outputs(native_output, candidate_output)
        after = {
            output: (
                (output / "report.md").stat().st_ino,
                (output / "report.md").stat().st_mtime_ns,
                tuple(
                    (path.name, path.stat().st_ino, path.stat().st_mtime_ns)
                    for path in self.receipts(output)
                ),
            )
            for output in (native_output, candidate_output)
        }
        self.assertEqual(after, before)

    def test_tamper_after_delivery_is_detected_without_rewriting_history(self) -> None:
        native, candidate, native_output, candidate_output = self.pair("tamper")
        self.assertEqual(native.deliver(native.authorize())["state"], "DELIVERED_RECEIPT")
        self.assertTrue(candidate.submit(self.content)["applied"])
        for output in (native_output, candidate_output):
            (output / "report.md").write_bytes(b"changed after delivery")
        with self.assertRaisesRegex(WorkspaceOperationError, "stored_outcome_file_mismatch"):
            native.fence()
        recovered = candidate.recover()
        self.assertEqual(recovered["state"], "UNKNOWN")
        self.assertEqual(recovered["recorded_outcome"], "DELIVERED_RECEIPT")
        self.assertFalse(recovered["current_verified"])
        self.assertEqual(candidate.status()["status"], "DELIVERED_RECEIPT")
        for output in (native_output, candidate_output):
            self.assertEqual((output / "report.md").read_bytes(), b"changed after delivery")
            self.assertEqual(len(self.receipts(output)), 1)

    def test_local_approval_denies_unapproved_and_changed_then_writes_exact_bytes(self) -> None:
        self.content = "Café — approved bytes\r\n第二行: exact.\r\n"
        reference, candidate, native_output, candidate_output = self.approval_pair("local-exact")
        self.assertEqual(reference.submit(self.content)["reason"], "not_approved")
        self.assertEqual(candidate.submit(self.content)["reason"], "not_approved")
        self.assertTrue(reference.approve())
        self.decide(candidate, "approve")
        changed = self.content.replace("\r\n", "\n")
        self.assertEqual(reference.submit(changed)["reason"], "object_changed")
        self.assertEqual(candidate.submit(changed)["reason"], "object_changed")
        for output in (native_output, candidate_output):
            self.assertFalse((output / "report.md").exists())
        self.assertTrue(reference.submit(self.content)["applied"])
        self.assertTrue(candidate.submit(self.content)["applied"])
        self.assert_exact_outputs(native_output, candidate_output)

    def test_local_approval_revoke_and_expiry_before_begin_refuse_both(self) -> None:
        for mode in ("revoke", "expired"):
            with self.subTest(mode=mode):
                reference, candidate, native_output, candidate_output = self.approval_pair(mode)
                self.assertTrue(reference.approve())
                self.decide(candidate, "approve")
                if mode == "revoke":
                    self.assertTrue(reference.revoke())
                    self.decide(candidate, "revoke")
                    expected = "not_approved"
                else:
                    self.now += 3600
                    expected = "expired"
                self.assertEqual(reference.submit(self.content)["reason"], expected)
                self.assertEqual(candidate.submit(self.content)["reason"], expected)
                for output in (native_output, candidate_output):
                    self.assertFalse((output / "report.md").exists())

    def test_local_approval_duplicate_is_spent_on_both(self) -> None:
        reference, candidate, native_output, candidate_output = self.approval_pair("local-duplicate")
        self.assertTrue(reference.approve())
        self.decide(candidate, "approve")
        self.assertTrue(reference.submit(self.content)["applied"])
        self.assertTrue(candidate.submit(self.content)["applied"])
        before = tuple(
            (output / "report.md").stat().st_mtime_ns
            for output in (native_output, candidate_output)
        )
        self.assertEqual(reference.submit(self.content)["reason"], "already_consumed")
        self.assertEqual(candidate.submit(self.content)["reason"], "already_consumed")
        self.assert_exact_outputs(native_output, candidate_output)
        after = tuple(
            (output / "report.md").stat().st_mtime_ns
            for output in (native_output, candidate_output)
        )
        self.assertEqual(after, before)
        self.assertEqual(reference.recover()["attempts_spent"], 1)
        self.assertTrue(candidate.recover()["current_verified"])

    def test_local_approval_failure_before_effect_spends_both_attempts(self) -> None:
        reference, candidate, native_output, candidate_output = self.approval_pair("before-effect")
        self.assertTrue(reference.approve())
        self.decide(candidate, "approve")
        with patch.object(WorkspaceOperation, "authorize", side_effect=OSError("synthetic failure")):
            native_result = reference.submit(self.content)
            candidate_result = candidate.submit(self.content)
        self.assertFalse(native_result["applied"])
        self.assertEqual(native_result["reason"], "UNKNOWN")
        self.assertFalse(candidate_result["applied"])
        self.assertEqual(candidate_result["status"], "UNKNOWN")
        self.assertEqual(reference.submit(self.content)["reason"], "already_consumed")
        self.assertEqual(candidate.submit(self.content)["reason"], "already_consumed")
        reference.recover()
        self.assertEqual(candidate.recover()["state"], "FENCED_ABSENT")
        for output in (native_output, candidate_output):
            self.assertFalse((output / "report.md").exists())
            self.assertEqual(self.receipts(output), ())

    def test_local_approval_failure_after_effect_recovers_without_replay(self) -> None:
        reference, candidate, native_output, candidate_output = self.approval_pair("after-effect")
        self.assertTrue(reference.approve())
        self.decide(candidate, "approve")
        original_save = ActionCore._save

        def fail_outer_outcome(self_core, state, *, kind=None, **kwargs):
            if kind == "outcome":
                raise sqlite3.OperationalError("synthetic post-effect state failure")
            return original_save(self_core, state, kind=kind, **kwargs)

        with patch.object(reference, "_record_outcome", side_effect=sqlite3.OperationalError):
            native_result = reference.submit(self.content)
        with patch.object(ActionCore, "_save", fail_outer_outcome):
            with self.assertRaises(sqlite3.OperationalError):
                candidate.submit(self.content)
        self.assertEqual(native_result, {"applied": False, "reason": "uncertain"})
        self.assert_exact_outputs(native_output, candidate_output)
        before = tuple(
            (output / "report.md").stat().st_mtime_ns
            for output in (native_output, candidate_output)
        )
        self.assertEqual(reference.recover()["state"], "DELIVERED_RECEIPT")
        recovered = candidate.recover()
        self.assertEqual(recovered["state"], "DELIVERED_RECEIPT")
        self.assertTrue(recovered["current_verified"])
        self.assertEqual(reference.submit(self.content)["reason"], "already_consumed")
        self.assertEqual(candidate.submit(self.content)["reason"], "already_consumed")
        after = tuple(
            (output / "report.md").stat().st_mtime_ns
            for output in (native_output, candidate_output)
        )
        self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main()
