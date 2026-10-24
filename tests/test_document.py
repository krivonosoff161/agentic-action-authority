"""Synthetic public-API journey for the installed create-only document host."""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ash_action_authority import (
    ActionCore,
    AuthorityError,
    DocumentHost,
    ProtocolError,
    canonical,
    decision_message,
)
from ash_action_authority.dispatch import TOOL_NAME
from ash_action_authority.operator import OperatorError


class DocumentHostJourneyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.home = self.root / "new-task"
        self.target = self.home / "output" / "document.md"
        self.signer = Ed25519PrivateKey.from_private_bytes(b"\x29" * 32)
        self.public_bytes = self.signer.public_key().public_bytes_raw()
        self.fingerprint = hashlib.sha256(self.public_bytes).hexdigest()
        self.public = self.root / "operator.hex"
        self.public.write_text(self.public_bytes.hex() + "\n", encoding="ascii")
        self.source = self.root / "source.txt"
        self.source.write_bytes(b"Declared synthetic public source.\n")
        self.document = self.root / "proposal.txt"
        self.content = "Proposed synthetic public document.\n"
        self.document.write_bytes(self.content.encode("utf-8"))
        self.decision_count = 0

    def prepare(self, **changes: object) -> DocumentHost:
        options: dict[str, object] = {
            "public_key": self.public,
            "expected_key_fingerprint": self.fingerprint,
            "source": self.source,
            "document": self.document,
            "host_repository": "example/document-host",
            "host_revision": "a" * 40,
            "allow_local_source_use": True,
        }
        options.update(changes)
        return DocumentHost.prepare(self.home, **options)

    def detached(self, request: dict, decision: str = "approve") -> Path:
        message = decision_message(request, decision=decision, issued_at=int(time.time()))
        signature = self.signer.sign(canonical(message))
        self.decision_count += 1
        path = self.root / f"synthetic-decision-{self.decision_count}.json"
        path.write_bytes(
            canonical(
                {
                    "message": message,
                    "signature_base64": base64.b64encode(signature).decode("ascii"),
                }
            )
        )
        return path

    def approve(self, host: DocumentHost) -> None:
        accepted = host.apply_decision(self.detached(host.request()))
        self.assertTrue(accepted["accepted"])
        self.assertEqual(accepted["reason"], "approved_exact_action")
        self.assertFalse(self.target.exists())

    def test_prepare_review_sign_apply_reopen_dispatch_and_readback(self) -> None:
        self.content = "Café — reviewed bytes\r\n第二行: exact.\r\n"
        self.document.write_bytes(self.content.encode("utf-8"))
        host = self.prepare()
        self.assertEqual(host.review_files, {
            "request": self.home / "request.json",
            "content": self.home / "document.txt",
        })
        self.assertEqual(host.status()["status"], "PENDING_APPROVAL")
        self.assertFalse(self.target.exists())
        review_request = json.loads(host.review_files["request"].read_text("ascii"))
        self.assertEqual(review_request, host.request())
        self.assertEqual(host.review_files["content"].read_bytes().decode("utf-8"), self.content)
        self.approve(host)
        reopened = DocumentHost.open(self.home)
        self.assertEqual(reopened.status()["status"], "APPROVED")
        descriptor = reopened.tool_descriptor()
        self.assertEqual(descriptor["name"], TOOL_NAME)
        self.assertEqual(set(descriptor["parameters"]["properties"]), {"content"})
        normalized = self.content.replace("\r\n", "\n")
        self.assertNotEqual(normalized, self.content)
        before = reopened.status()["control_events"]
        self.assertEqual(
            reopened.bind_tool()(TOOL_NAME, {"content": normalized}),
            {"outcome": "refused", "reason": "object_changed"},
        )
        self.assertEqual(reopened.status()["control_events"], before)
        self.assertFalse(self.target.exists())
        self.assertEqual(
            reopened.bind_tool()(TOOL_NAME, {"content": self.content}),
            {"outcome": "applied", "reason": "writer_receipt_recorded"},
        )
        self.assertEqual(self.target.read_bytes(), self.content.encode("utf-8"))
        recovered = DocumentHost.open(self.home).status(recover=True)
        self.assertEqual(recovered["state"], "DELIVERED_RECEIPT")
        self.assertTrue(recovered["current_verified"])

    def test_changed_content_denied_without_spending_then_exact_content_applies(self) -> None:
        host = self.prepare()
        self.approve(host)
        before = host.status()["control_events"]
        dispatch = host.bind_tool()
        self.assertEqual(
            dispatch(TOOL_NAME, {"content": self.content + "altered"}),
            {"outcome": "refused", "reason": "object_changed"},
        )
        self.assertEqual(host.status()["control_events"], before)
        self.assertFalse(self.target.exists())
        self.assertEqual(dispatch(TOOL_NAME, {"content": self.content})["outcome"], "applied")

    def test_replay_refused_without_second_file_effect(self) -> None:
        host = self.prepare()
        self.approve(host)
        dispatch = host.bind_tool()
        self.assertEqual(dispatch(TOOL_NAME, {"content": self.content})["outcome"], "applied")
        before = self.target.stat()
        self.assertEqual(
            DocumentHost.open(self.home).bind_tool()(TOOL_NAME, {"content": self.content}),
            {"outcome": "refused", "reason": "already_consumed"},
        )
        after = self.target.stat()
        self.assertEqual(
            (after.st_dev, after.st_ino, after.st_mtime_ns),
            (before.st_dev, before.st_ino, before.st_mtime_ns),
        )

    def test_invalid_tool_and_authority_fields_refused_before_state_open(self) -> None:
        missing = self.root / "missing-home"
        dispatch = DocumentHost(missing).bind_tool()
        self.assertEqual(
            dispatch("apply_decision", {"content": self.content}),
            {"outcome": "refused", "reason": "unknown_tool"},
        )
        for arguments in (
            None,
            {"content": self.content, "path": str(self.target)},
            {"content": self.content, "approve": True},
            {"content": self.content, "public_key": self.public_bytes.hex()},
        ):
            with self.subTest(arguments=type(arguments).__name__):
                self.assertEqual(
                    dispatch(TOOL_NAME, arguments),
                    {"outcome": "refused", "reason": "invalid_arguments"},
                )
        self.assertFalse(missing.exists())
        self.assertFalse(self.target.exists())

    def test_missing_home_and_export_request_never_create_or_overwrite_state(self) -> None:
        missing = self.root / "missing-home"
        with self.assertRaises((AuthorityError, OSError)):
            DocumentHost.open(missing)
        self.assertFalse(missing.exists())
        host = self.prepare()
        exported = self.root / "exported-request.json"
        host.export_request(exported)
        self.assertEqual(json.loads(exported.read_text("ascii")), host.request())
        before = exported.read_bytes()
        with self.assertRaises(OperatorError):
            host.export_request(exported)
        self.assertEqual(exported.read_bytes(), before)

    def test_retained_source_change_is_uncertain_without_file_effect(self) -> None:
        host = self.prepare()
        self.approve(host)
        (self.home / "source.txt").write_bytes(b"Changed retained synthetic source.\n")
        self.assertEqual(
            host.bind_tool()(TOOL_NAME, {"content": self.content}),
            {"outcome": "uncertain", "reason": "host_recovery_required"},
        )
        with self.assertRaisesRegex(AuthorityError, "retained_input_changed"):
            DocumentHost.open(self.home)
        with self.assertRaisesRegex(AuthorityError, "retained_input_changed"):
            host.status(recover=True)
        # This fixture has no file effect; the generic uncertain result does not prove absence.
        self.assertFalse(self.target.exists())

    def test_expired_approval_refuses_without_effect(self) -> None:
        host = self.prepare(valid_seconds=60)
        self.approve(host)
        expires_at = host.request()["expires_at"]
        with patch.object(ActionCore, "_now", return_value=expires_at):
            result = host.bind_tool()(TOOL_NAME, {"content": self.content})
        self.assertEqual(result, {"outcome": "refused", "reason": "expired"})
        self.assertFalse(self.target.exists())

    def test_revoke_before_begin_invalidates_old_signed_approval(self) -> None:
        host = self.prepare()
        old_request = host.request()
        old_approval = self.detached(old_request)
        revoked = host.apply_decision(self.detached(old_request, "revoke"))
        self.assertEqual(revoked["reason"], "revoked_before_begin")
        self.assertEqual(host.status()["status"], "PENDING_APPROVAL")
        self.assertNotEqual(host.request()["challenge"], old_request["challenge"])
        with self.assertRaises(ProtocolError):
            host.apply_decision(old_approval)
        self.assertFalse(self.target.exists())
        fresh = self.root / "fresh-request.json"
        host.export_request(fresh)
        self.assertEqual(json.loads(fresh.read_text("ascii")), host.request())

    def test_post_effect_save_failure_is_uncertain_and_recovery_never_replays(self) -> None:
        host = self.prepare()
        self.approve(host)
        original_save = ActionCore._save

        def fail_outer_outcome(self_core, state, *, kind=None, **kwargs):
            if kind == "outcome":
                raise sqlite3.OperationalError("synthetic_post_effect_save_failure")
            return original_save(self_core, state, kind=kind, **kwargs)

        with patch.object(ActionCore, "_save", fail_outer_outcome):
            result = host.bind_tool()(TOOL_NAME, {"content": self.content})
        self.assertEqual(result, {"outcome": "uncertain", "reason": "host_recovery_required"})
        self.assertEqual(self.target.read_bytes(), self.content.encode("utf-8"))
        before = self.target.stat()
        self.assertEqual(host.status()["status"], "EXECUTING")
        recovered = DocumentHost.open(self.home).status(recover=True)
        self.assertEqual(recovered["state"], "DELIVERED_RECEIPT")
        self.assertEqual(recovered["recorded_outcome"], "EXECUTING")
        self.assertTrue(recovered["current_verified"])
        after = self.target.stat()
        self.assertEqual(
            (after.st_dev, after.st_ino, after.st_mtime_ns),
            (before.st_dev, before.st_ino, before.st_mtime_ns),
        )
        self.assertEqual(
            host.bind_tool()(TOOL_NAME, {"content": self.content}),
            {"outcome": "refused", "reason": "already_consumed"},
        )

    def test_host_execute_requires_approval_and_accepts_no_arguments(self) -> None:
        host = self.prepare()
        self.assertEqual(
            host.execute_approved(), {"outcome": "refused", "reason": "not_approved"}
        )
        self.assertFalse(self.target.exists())
        with self.assertRaises(TypeError):
            host.execute_approved(self.content)
        with self.assertRaises(TypeError):
            host.execute_approved(content=self.content)
        with self.assertRaises(TypeError):
            host.execute_approved(path=self.target)
        with self.assertRaises(TypeError):
            host.execute_approved(approve=True)
        self.assertFalse(self.target.exists())
        descriptor = host.tool_descriptor()
        self.assertEqual(descriptor["name"], TOOL_NAME)
        self.assertEqual(set(descriptor["parameters"]["properties"]), {"content"})

    def test_host_execute_uses_retained_exact_bytes_without_original_proposal(self) -> None:
        self.content = "Café — reviewed bytes\r\n第二行: exact.\r\n"
        for original_state in ("changed", "removed"):
            with self.subTest(original_state=original_state):
                self.home = self.root / f"task-{original_state}"
                self.target = self.home / "output" / "document.md"
                self.document.write_bytes(self.content.encode("utf-8"))
                host = self.prepare()
                self.approve(host)
                if original_state == "changed":
                    self.document.write_bytes(b"changed original proposal\n")
                else:
                    self.document.unlink()
                self.assertEqual(
                    DocumentHost.open(self.home).execute_approved(),
                    {"outcome": "applied", "reason": "writer_receipt_recorded"},
                )
                self.assertEqual(self.target.read_bytes(), self.content.encode("utf-8"))
                recovered = host.status(recover=True)
                self.assertEqual(recovered["state"], "DELIVERED_RECEIPT")
                self.assertTrue(recovered["current_verified"])

    def test_host_execute_refuses_changed_retained_inputs_without_effect(self) -> None:
        for name in ("document.txt", "source.txt"):
            with self.subTest(name=name):
                self.home = self.root / f"task-{name}"
                self.target = self.home / "output" / "document.md"
                host = self.prepare()
                self.approve(host)
                (self.home / name).write_bytes(b"changed retained input\n")
                self.assertEqual(
                    host.execute_approved(),
                    {"outcome": "uncertain", "reason": "host_recovery_required"},
                )
                self.assertFalse(self.target.exists())

    def test_host_execute_replay_is_refused_without_second_effect(self) -> None:
        host = self.prepare()
        self.approve(host)
        self.assertEqual(host.execute_approved()["outcome"], "applied")
        before = self.target.stat()
        self.assertEqual(
            DocumentHost.open(self.home).execute_approved(),
            {"outcome": "refused", "reason": "already_consumed"},
        )
        after = self.target.stat()
        self.assertEqual(
            (after.st_dev, after.st_ino, after.st_mtime_ns),
            (before.st_dev, before.st_ino, before.st_mtime_ns),
        )

    def test_host_execute_expiry_refuses_without_effect(self) -> None:
        host = self.prepare(valid_seconds=60)
        self.approve(host)
        with patch.object(ActionCore, "_now", return_value=host.request()["expires_at"]):
            result = host.execute_approved()
        self.assertEqual(result, {"outcome": "refused", "reason": "expired"})
        self.assertFalse(self.target.exists())

    def test_host_execute_revocation_requires_fresh_challenge_approval(self) -> None:
        host = self.prepare()
        old_request = host.request()
        old_approval = self.detached(old_request)
        self.assertEqual(
            host.apply_decision(self.detached(old_request, "revoke"))["reason"],
            "revoked_before_begin",
        )
        self.assertNotEqual(host.request()["challenge"], old_request["challenge"])
        with self.assertRaises(ProtocolError):
            host.apply_decision(old_approval)
        self.assertEqual(
            host.execute_approved(), {"outcome": "refused", "reason": "not_approved"}
        )
        self.assertFalse(self.target.exists())
        self.approve(host)
        self.assertEqual(host.execute_approved()["outcome"], "applied")

    def test_host_execute_post_effect_save_failure_recovers_without_replay(self) -> None:
        host = self.prepare()
        self.approve(host)
        original_save = ActionCore._save

        def fail_outer_outcome(self_core, state, *, kind=None, **kwargs):
            if kind == "outcome":
                raise sqlite3.OperationalError("synthetic_post_effect_save_failure")
            return original_save(self_core, state, kind=kind, **kwargs)

        with patch.object(ActionCore, "_save", fail_outer_outcome):
            result = host.execute_approved()
        self.assertEqual(result, {"outcome": "uncertain", "reason": "host_recovery_required"})
        self.assertEqual(self.target.read_bytes(), self.content.encode("utf-8"))
        before = self.target.stat()
        recovered = DocumentHost.open(self.home).status(recover=True)
        self.assertEqual(recovered["state"], "DELIVERED_RECEIPT")
        self.assertTrue(recovered["current_verified"])
        after = self.target.stat()
        self.assertEqual(
            (after.st_dev, after.st_ino, after.st_mtime_ns),
            (before.st_dev, before.st_ino, before.st_mtime_ns),
        )
        self.assertEqual(
            host.execute_approved(), {"outcome": "refused", "reason": "already_consumed"}
        )


if __name__ == "__main__":
    unittest.main()
