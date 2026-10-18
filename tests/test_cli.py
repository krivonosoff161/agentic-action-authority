"""Content-free host CLI results; all paths and keys are synthetic fixtures."""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ash_action_authority import canonical, decision_message, host


class HostCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.home = self.root / "new-home"

    def cli(self, *arguments: str) -> tuple[int, dict, str]:
        if arguments[0] == "setup":
            arguments = (*arguments, "--host-repository", "fixture/document-host",
                         "--expected-key-fingerprint", getattr(self, "fingerprint", "0" * 64))
        shown = StringIO()
        with redirect_stdout(shown):
            code = host.main(list(arguments))
        raw = shown.getvalue()
        return code, json.loads(raw), raw

    def test_missing_setup_input_returns_content_free_nonzero_json(self) -> None:
        code, result, raw = self.cli(
            "setup",
            "--home",
            str(self.home),
            "--public-key",
            str(self.root / "absent.hex"),
            "--source",
            str(self.root / "absent-source"),
            "--document",
            str(self.root / "absent-document"),
            "--host-revision",
            "a" * 40,
            "--allow-local-source-use",
        )
        self.assertEqual(code, 1)
        self.assertEqual(set(result), {"ok", "reason", "next_step"})
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "input_or_state_refused")
        self.assertIn("public input paths", result["next_step"])
        self.assertNotIn(str(self.root), raw)
        self.assertFalse(self.home.exists())

    def test_existing_home_requires_new_directory(self) -> None:
        self.home.mkdir()
        code, result, raw = self.cli(
            "setup",
            "--home",
            str(self.home),
            "--public-key",
            str(self.root / "absent.hex"),
            "--source",
            str(self.root / "absent-source"),
            "--document",
            str(self.root / "absent-document"),
            "--host-revision",
            "a" * 40,
            "--allow-local-source-use",
        )
        self.assertEqual(code, 1)
        self.assertEqual(result["reason"], "home_exists_use_new_directory")
        self.assertIn("new empty directory", result["next_step"])
        self.assertNotIn(str(self.root), raw)

    def test_malformed_detached_decision_refuses_without_echo(self) -> None:
        decision = self.root / "malformed-decision.json"
        decision.write_bytes(b'{"private":"SENSITIVE-FIXTURE",broken}')
        code, result, raw = self.cli(
            "apply-decision", "--home", str(self.home), "--decision", str(decision)
        )
        self.assertEqual(code, 1)
        self.assertEqual(result["reason"], "decision_invalid_or_unverified")
        self.assertIn("operator review", result["next_step"])
        self.assertNotIn("SENSITIVE-FIXTURE", raw)
        self.assertNotIn(str(decision), raw)

    def test_refused_run_exits_nonzero_without_creating_target(self) -> None:
        signer = Ed25519PrivateKey.generate()
        public = signer.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        public_path = self.root / "synthetic-public.hex"
        self.fingerprint = hashlib.sha256(public).hexdigest()
        public_path.write_text(public.hex(), encoding="ascii")
        source = self.root / "declared-public-source.txt"
        source.write_bytes(b"Synthetic public source.\n")
        document = self.root / "proposal.txt"
        document.write_bytes(b"Synthetic proposed document.\n")
        setup_code, _, _ = self.cli(
            "setup",
            "--home",
            str(self.home),
            "--public-key",
            str(public_path),
            "--source",
            str(source),
            "--document",
            str(document),
            "--host-revision",
            "a" * 40,
            "--allow-local-source-use",
        )
        self.assertEqual(setup_code, 0)
        code, result, raw = self.cli("run", "--home", str(self.home))
        self.assertEqual(code, 1)
        self.assertFalse(result["applied"])
        self.assertEqual(result["reason"], "not_approved")
        self.assertIn("operator decision", result["next_step"])
        self.assertNotIn("Synthetic proposed document", raw)
        self.assertFalse((self.home / "output" / "document.md").exists())

    def test_synthetic_post_effect_sql_failure_reports_unknown_not_no_effect(self) -> None:
        target = self.root / "synthetic-target.txt"

        class EffectThenStorageFailure:
            content = "Synthetic public document."

            def submit(self, content: str) -> dict:
                target.write_text(content, encoding="utf-8")
                raise sqlite3.OperationalError("SENSITIVE-FIXTURE storage detail")

        with patch("ash_action_authority.host._restore", return_value=EffectThenStorageFailure()):
            code, result, raw = self.cli("run", "--home", str(self.home))
        self.assertEqual(code, 2)
        self.assertEqual(result["reason"], "effect_outcome_unknown")
        self.assertIn("status --recover", result["next_step"])
        self.assertIn("do not replay", result["next_step"])
        self.assertEqual(target.read_text(encoding="utf-8"), "Synthetic public document.")
        self.assertNotIn("SENSITIVE-FIXTURE", raw)
        self.assertNotIn("no_effect", raw)

    def test_busy_approval_reports_no_acknowledgement(self) -> None:
        with patch(
            "ash_action_authority.host.apply", side_effect=host.AuthorityBusy("SENSITIVE-FIXTURE")
        ):
            code, result, raw = self.cli(
                "apply-decision",
                "--home",
                str(self.home),
                "--decision",
                str(self.root / "decision.json"),
            )
        self.assertEqual(code, 2)
        self.assertEqual(result["reason"], "busy_no_decision_acknowledged")
        self.assertIn("No decision was acknowledged", result["next_step"])
        self.assertNotIn("SENSITIVE-FIXTURE", raw)

    def test_known_setup_errors_are_actionable_without_echoing_input(self) -> None:
        for reason, expected in (
            ("operator_key_mismatch", "independent trusted channel"),
            ("invalid_expected_key_fingerprint", "separately verified"),
            ("invalid_host_provenance", "owner/repository"),
            ("host_must_authorize_local_public_source_use", "explicitly authorize"),
        ):
            with self.subTest(reason=reason), patch(
                "ash_action_authority.host.setup", side_effect=host.AuthorityError(reason)
            ):
                code, result, raw = self.cli(
                    "setup", "--home", str(self.home), "--public-key", "public.hex",
                    "--source", "SENSITIVE-FIXTURE-source", "--document", "proposal.txt",
                    "--host-revision", "a" * 40, "--allow-local-source-use",
                )
                self.assertEqual(code, 1)
                self.assertEqual(result["reason"], reason)
                self.assertIn(expected, result["next_step"])
                self.assertNotIn("SENSITIVE-FIXTURE", raw)
                self.assertFalse(self.home.exists())

    def test_expired_decision_requires_new_task_not_renewal(self) -> None:
        signer = Ed25519PrivateKey.from_private_bytes(b"\x37" * 32)
        public_bytes = signer.public_key().public_bytes_raw()
        self.fingerprint = hashlib.sha256(public_bytes).hexdigest()
        public = self.root / "synthetic-operator.hex"
        public.write_bytes(public_bytes.hex().encode("ascii") + b"\n")
        source = self.root / "synthetic-source.txt"
        source.write_bytes(b"Declared synthetic public source.\n")
        document = self.root / "synthetic-proposal.txt"
        document.write_bytes(b"Exact synthetic public document.\n")
        setup_code, _, _ = self.cli(
            "setup", "--home", str(self.home), "--public-key", str(public),
            "--source", str(source), "--document", str(document),
            "--host-revision", "a" * 40, "--valid-seconds", "60",
            "--allow-local-source-use",
        )
        self.assertEqual(setup_code, 0)
        request = json.loads((self.home / "request.json").read_text(encoding="ascii"))
        expires_at = request["expires_at"]

        def signed_decision(path: Path, issued_at: int) -> Path:
            message = decision_message(request, decision="approve", issued_at=issued_at)
            path.write_bytes(canonical({
                "message": message,
                "signature_base64": base64.b64encode(signer.sign(canonical(message))).decode("ascii"),
            }))
            return path

        expired = signed_decision(self.root / "expired-decision.json", expires_at - 2)
        with patch("ash_action_authority.host.time.time", return_value=expires_at):
            code, result, raw = self.cli(
                "apply-decision", "--home", str(self.home), "--decision", str(expired)
            )
        self.assertEqual(code, 1)
        self.assertEqual(result["reason"], "approval_expired")
        self.assertIn("new task", result["next_step"])
        self.assertIn("do not extend", result["next_step"])
        self.assertNotIn(str(expired), raw)
        self.assertFalse((self.home / "output" / "document.md").exists())

        future = signed_decision(self.root / "future-decision.json", expires_at - 1)
        with patch("ash_action_authority.host.time.time", return_value=expires_at - 2):
            code, result, raw = self.cli(
                "apply-decision", "--home", str(self.home), "--decision", str(future)
            )
        self.assertEqual(code, 1)
        self.assertEqual(result["reason"], "decision_invalid_or_unverified")
        self.assertNotIn(str(future), raw)
        self.assertFalse((self.home / "output" / "document.md").exists())

    def test_run_refusals_have_specific_safe_next_steps(self) -> None:
        for reason, expected in (
            ("not_approved", "operator decision"),
            ("object_changed", "new task"),
            ("expired", "new operator decision"),
            ("already_consumed", "do not submit it again"),
        ):
            with self.subTest(reason=reason), redirect_stdout(StringIO()) as shown:
                code = host._cli_result("run", {"applied": False, "reason": reason})
                self.assertEqual(code, 1)
                self.assertIn(expected, json.loads(shown.getvalue())["next_step"])


if __name__ == "__main__":
    unittest.main()
