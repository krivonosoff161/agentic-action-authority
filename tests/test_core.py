"""Synthetic effect-port checks; no production effect or human approval."""

from __future__ import annotations

import hashlib
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import ash_action_authority
from ash_action_authority import ActionCore, canonical, decision_message
from ash_action_authority.protocol import GENERIC_REQUEST_DOMAIN, ProtocolError, build_request


class FixtureOperation:
    def __init__(self, effect):
        self.effect = effect

    def authorize(self):
        self.effect.calls.append("authorize")
        return object()

    def deliver(self, permission):
        self.effect.calls.append("deliver")
        return self.effect.outcome

    def fence(self):
        self.effect.calls.append("fence")
        return self.effect.outcome


class FixtureEffect:
    request_domain = GENERIC_REQUEST_DOMAIN
    max_bytes = 65536

    def __init__(self, content, public_key):
        raw = content.encode()
        self.binding = {
            "app_id": "fixture-app", "task_id": "fixture-task",
            "operation_id": "fixture-operation", "initiator": "fixture-agent",
            "action": "synthetic-effect", "target": "fixture-target",
            "effect_contract_sha256": hashlib.sha256(b"fixture-effect-v1").hexdigest(),
            "payload_sha256": hashlib.sha256(raw).hexdigest(),
            "payload_length": len(raw),
            "dependencies": {"source": hashlib.sha256(b"fixture-source").hexdigest()},
            "operator_key_fingerprint": hashlib.sha256(public_key).hexdigest(),
        }
        self.calls = []
        self.outcome = {"state": "UNKNOWN", "reason": "fixture_uncertain"}

    def check(self):
        self.calls.append("check")

    def create(self, state_path):
        state_path.write_bytes(b"fixture-operation-state")

    def open(self, state_path):
        if state_path.read_bytes() != b"fixture-operation-state":
            raise ValueError("fixture_state_changed")
        return FixtureOperation(self)

    def target_absent(self):
        self.calls.append("target_absent")
        return True


class CoreTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory(prefix="aa-core-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.signer = Ed25519PrivateKey.generate()
        self.content = "synthetic content"
        self.effect = FixtureEffect(self.content, self.signer.public_key().public_bytes_raw())
        self.now = 1_800_000_000
        self.gate = ActionCore.create(
            self.base / "state", self.effect, content=self.content,
            public_key=self.signer.public_key().public_bytes_raw(), key_id="fixture-key",
            app_id="fixture-app", task_id="fixture-task", initiator="fixture-agent",
            expires_at=self.now + 3600, clock=lambda: self.now)

    def decide(self, decision="approve"):
        message = decision_message(self.gate.request(), decision=decision, issued_at=self.now)
        return self.gate.apply_decision(message, self.signer.sign(canonical(message)))

    def test_base_import_did_not_load_harness(self):
        selected = Path(ash_action_authority.__file__).resolve()
        package_root = selected.parent.parent
        probe = (
            "import sys, pathlib; sys.path.insert(0, sys.argv[1]); "
            "sys.modules['agentic_security_harness'] = None; "
            "import ash_action_authority; "
            "assert pathlib.Path(ash_action_authority.__file__).resolve() == pathlib.Path(sys.argv[2]); "
            "from ash_action_authority import ActionCore, canonical; "
            "assert ActionCore and canonical; "
            "assert not any(x.startswith('agentic_security_harness.') for x in sys.modules)"
        )
        result = subprocess.run([sys.executable, "-I", "-c", probe,
                                 str(package_root), str(selected)],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_host_cli_names_missing_optional_extra(self):
        selected = Path(ash_action_authority.__file__).resolve()
        package_root = selected.parent.parent
        probe = (
            "import sys, pathlib, importlib.util, runpy; sys.path.insert(0, sys.argv[1]); "
            "import ash_action_authority; "
            "assert pathlib.Path(ash_action_authority.__file__).resolve() == pathlib.Path(sys.argv[2]); "
            "original = importlib.util.find_spec; "
            "importlib.util.find_spec = lambda name: None if name == "
            "'agentic_security_harness' else original(name); "
            "runpy.run_module('ash_action_authority.host', run_name='__main__')"
        )
        result = subprocess.run([sys.executable, "-I", "-c", probe,
                                 str(package_root), str(selected)],
                                capture_output=True, text=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("agentic-action-authority[harness]", result.stderr)

    def test_document_host_names_missing_optional_extra_without_core_side_effect(self):
        selected = Path(ash_action_authority.__file__).resolve()
        probe = "\n".join((
            "import sys",
            "sys.path.insert(0, sys.argv[1])",
            "sys.modules['agentic_security_harness'] = None",
            "import ash_action_authority",
            "assert 'ash_action_authority.document' not in sys.modules",
            "try:",
            "    from ash_action_authority import DocumentHost",
            "except ImportError as exc:",
            "    assert 'agentic-action-authority[harness]' in str(exc)",
            "else:",
            "    raise AssertionError('missing adapter must not import')",
            "assert ash_action_authority.ActionCore",
        ))
        result = subprocess.run(
            [sys.executable, "-I", "-c", probe, str(selected.parent.parent)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_generic_schema_and_domain_are_closed(self):
        request = self.gate.request()
        self.assertEqual(request["domain"], GENERIC_REQUEST_DOMAIN)
        invalid = {**self.effect.binding, "unreviewed_field": "value"}
        with self.assertRaises(ProtocolError):
            build_request(invalid, epoch=0, challenge="0" * 64,
                          expires_at=self.now + 1, key_id="fixture-key",
                          domain=GENERIC_REQUEST_DOMAIN)

    def test_revoke_and_exact_content_before_begin(self):
        self.assertTrue(self.decide("approve")["accepted"])
        self.assertEqual(self.gate.submit("changed")["reason"], "object_changed")
        self.assertTrue(self.decide("revoke")["accepted"])
        self.assertEqual(self.gate.submit(self.content)["reason"], "not_approved")
        self.assertNotIn("authorize", self.effect.calls)

    def test_unknown_recovery_never_delivers_again(self):
        self.assertTrue(self.decide()["accepted"])
        self.assertEqual(self.gate.submit(self.content)["status"], "UNKNOWN")
        self.assertEqual(self.effect.calls.count("deliver"), 1)
        self.gate.recover()
        self.assertEqual(self.effect.calls.count("deliver"), 1)
        self.assertEqual(self.gate.submit(self.content)["reason"], "already_consumed")

    def test_malformed_adapter_success_is_uncertain(self):
        self.effect.outcome = {"state": "DELIVERED_RECEIPT", "reason": "unproved"}
        self.assertTrue(self.decide()["accepted"])
        self.assertEqual(self.gate.submit(self.content)["status"], "UNKNOWN")
        self.assertEqual(self.gate.recover()["state"], "UNKNOWN")
        self.assertEqual(self.effect.calls.count("deliver"), 1)

    def test_effect_binding_mismatch_refuses_state_reopen(self):
        self.effect.binding["target"] = "changed-target"
        with self.assertRaisesRegex(Exception, "unsealed_or_different_setup"):
            ActionCore.open(
                self.base / "state", self.effect, content=self.content,
                public_key=self.signer.public_key().public_bytes_raw(), key_id="fixture-key",
                app_id="fixture-app", task_id="fixture-task", initiator="fixture-agent",
                expires_at=self.now + 3600, clock=lambda: self.now)

    def test_caller_or_effect_binding_mutation_cannot_change_approved_target(self):
        viewed = self.gate.binding
        viewed["target"] = "unapproved-target"
        self.assertEqual(self.gate.request()["binding"]["target"], "fixture-target")
        self.assertTrue(self.decide()["accepted"])
        self.effect.binding["target"] = "unapproved-target"
        with self.assertRaisesRegex(Exception, "effect_binding_changed"):
            self.gate.submit(self.content)
        self.assertNotIn("authorize", self.effect.calls)

    def test_nested_binding_mutation_cannot_change_approved_dependencies(self):
        viewed = self.gate.binding
        viewed["dependencies"]["source"] = "0" * 64
        self.assertEqual(self.gate.request()["binding"]["dependencies"],
                         self.effect.binding["dependencies"])
        self.assertTrue(self.decide()["accepted"])
        self.effect.binding["dependencies"]["source"] = "1" * 64
        with self.assertRaisesRegex(Exception, "effect_binding_changed"):
            self.gate.submit(self.content)
        self.assertNotIn("authorize", self.effect.calls)

    def test_nested_binding_mutation_refuses_state_reopen(self):
        self.effect.binding["dependencies"]["source"] = "1" * 64
        with self.assertRaisesRegex(Exception, "unsealed_or_different_setup"):
            ActionCore.open(
                self.base / "state", self.effect, content=self.content,
                public_key=self.signer.public_key().public_bytes_raw(), key_id="fixture-key",
                app_id="fixture-app", task_id="fixture-task", initiator="fixture-agent",
                expires_at=self.now + 3600, clock=lambda: self.now)


if __name__ == "__main__":
    unittest.main()
