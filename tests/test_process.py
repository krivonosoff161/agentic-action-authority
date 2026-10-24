"""Actual finite child-process races/deaths on owned fixture files, no model."""

import base64
import hashlib
import multiprocessing as mp
import os
import tempfile
import time
import unittest
from pathlib import Path

from agentic_security_harness.workspace_writer import GuardedWorkspace, WorkspacePolicy
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ash_action_authority import (
    ActionCore,
    ActionGate,
    AuthorityBusy,
    DocumentHost,
    canonical,
    decision_message,
)


def child(root, policy, config, mode, start, entered, release, results):
    gate = ActionGate.open(root, policy, **config)
    if mode == "after_begin":
        original = gate._save

        def save(state, **kwargs):
            original(state, **kwargs)
            if kwargs.get("kind") == "begin":
                os._exit(81)

        gate._save = save
    elif mode == "after_permission":
        factory = gate._operation

        def operation():
            op = factory()
            authorize = op.authorize

            def crash_authorize():
                authorize()
                os._exit(82)

            op.authorize = crash_authorize
            return op

        gate._operation = operation
    elif mode == "after_file_before_core_commit":
        submit = GuardedWorkspace.submit

        def crash_submit(self, proposal):
            result = submit(self, proposal)
            if result.get("applied"):
                os._exit(83)
            return result

        GuardedWorkspace.submit = crash_submit
    elif mode == "before_outer_outcome":
        original = gate._save

        def save(state, **kwargs):
            if kwargs.get("kind") == "outcome":
                os._exit(84)
            return original(state, **kwargs)

        gate._save = save
    elif mode == "slow_delivery":
        factory = gate._operation

        def operation():
            op = factory()
            deliver = op.deliver

            def blocked(permission):
                entered.set()
                if not release.wait(20):
                    raise RuntimeError("fixture_release_timeout")
                return deliver(permission)

            op.deliver = blocked
            return op

        gate._operation = operation
    if start is not None and not start.wait(20):
        raise RuntimeError("fixture_start_timeout")
    results.put(gate.submit(config["content"]))


def document_child(home, mode, start, entered, release, results):
    """Use the public host route in a finite spawned process."""
    if mode in ("after_begin", "before_outer_outcome"):
        original_save = ActionCore._save

        def save(self_core, state, **kwargs):
            if mode == "before_outer_outcome" and kwargs.get("kind") == "outcome":
                os._exit(94)
            original_save(self_core, state, **kwargs)
            if mode == "after_begin" and kwargs.get("kind") == "begin":
                os._exit(91)

        ActionCore._save = save
    elif mode in ("after_permission", "slow_delivery"):
        original_operation = ActionCore._operation

        def operation(self_core):
            op = original_operation(self_core)
            if mode == "after_permission":
                authorize = op.authorize

                def crash_authorize():
                    authorize()
                    os._exit(92)

                op.authorize = crash_authorize
            else:
                deliver = op.deliver

                def blocked(permission):
                    entered.set()
                    if not release.wait(20):
                        raise RuntimeError("fixture_release_timeout")
                    return deliver(permission)

                op.deliver = blocked
            return op

        ActionCore._operation = operation
    elif mode == "after_file_before_receipt":
        original_submit = GuardedWorkspace.submit

        def crash_submit(self, proposal):
            result = original_submit(self, proposal)
            if result.get("applied"):
                os._exit(93)
            return result

        GuardedWorkspace.submit = crash_submit
    if start is not None and not start.wait(20):
        raise RuntimeError("fixture_start_timeout")
    results.put(DocumentHost.open(home).execute_approved())


class ProcessChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ash-signed-process-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.ctx = mp.get_context("spawn")

    def fixture(self, name):
        base = self.base / name
        base.mkdir()
        output = base / "output"
        output.mkdir()
        (output / "protected.txt").write_bytes(b"unchanged")
        policy = WorkspacePolicy(output, (("report", "report.md"),), data_class="public")
        key = Ed25519PrivateKey.generate()
        config = dict(
            content="Actual process fixture report.\n",
            operation_id=hashlib.sha256(name.encode()).hexdigest(),
            artifact="report",
            public_key=key.public_key().public_bytes_raw(),
            key_id="fixture-key",
            app_id="process-test",
            task_id=name,
            initiator="fixture-agent",
            expires_at=int(time.time()) + 3600,
        )
        root = base / "authority"
        gate = ActionGate.create(root, policy, **config)
        message = decision_message(gate.request(), decision="approve", issued_at=int(time.time()))
        gate.apply_decision(message, key.sign(canonical(message)))
        return root, policy, config, gate, key

    def launch(self, root, policy, config, mode, start=None, entered=None, release=None):
        results = self.ctx.Queue()
        p = self.ctx.Process(
            target=child, args=(root, policy, config, mode, start, entered, release, results)
        )
        p.start()

        def cleanup():
            if p.is_alive():
                p.terminate()
                p.join(5)
            results.close()

        self.addCleanup(cleanup)
        return p, results

    def document_fixture(self, name):
        base = self.base / f"document-{name}"
        base.mkdir()
        home = base / "task"
        key = Ed25519PrivateKey.generate()
        public_bytes = key.public_key().public_bytes_raw()
        public = base / "operator.hex"
        public.write_text(public_bytes.hex() + "\n", encoding="ascii")
        source = base / "source.txt"
        source.write_bytes(b"Declared synthetic public source.\n")
        content = "Café — reviewed bytes\r\n第二行: exact.\r\n"
        proposal = base / "proposal.txt"
        proposal.write_bytes(content.encode("utf-8"))
        host = DocumentHost.prepare(
            home,
            public_key=public,
            expected_key_fingerprint=hashlib.sha256(public_bytes).hexdigest(),
            source=source,
            document=proposal,
            host_repository="example/document-host",
            host_revision="a" * 40,
            allow_local_source_use=True,
        )
        message = decision_message(host.request(), decision="approve", issued_at=int(time.time()))
        detached = base / "approved.json"
        detached.write_bytes(canonical({
            "message": message,
            "signature_base64": base64.b64encode(key.sign(canonical(message))).decode("ascii"),
        }))
        self.assertTrue(host.apply_decision(detached)["accepted"])
        target = home / "output" / "document.md"
        protected = home / "output" / "protected.txt"
        protected.write_bytes(b"unchanged")
        return host, key, content.encode("utf-8"), target, protected

    def launch_document(self, home, mode="normal", start=None, entered=None, release=None):
        results = self.ctx.Queue()
        process = self.ctx.Process(
            target=document_child, args=(home, mode, start, entered, release, results)
        )
        process.start()

        def cleanup():
            if process.is_alive():
                process.terminate()
                process.join(5)
            results.close()

        self.addCleanup(cleanup)
        return process, results

    def test_two_real_processes_admit_only_one_effect(self):
        root, policy, config, gate, _ = self.fixture("race")
        start = self.ctx.Event()
        first, one = self.launch(root, policy, config, "normal", start=start)
        second, two = self.launch(root, policy, config, "normal", start=start)
        start.set()
        first.join(20)
        second.join(20)
        self.assertEqual((first.exitcode, second.exitcode), (0, 0))
        observed = [one.get(timeout=2), two.get(timeout=2)]
        self.assertEqual(sum(v["applied"] for v in observed), 1)
        self.assertEqual(
            sorted(v["reason"] for v in observed), ["already_consumed", "writer_receipt_durable"]
        )
        self.assertTrue(gate.recover()["current_verified"])

    def test_actual_crash_points_recover_without_delivery_replay(self):
        variants = [
            ("after_begin", 81, "FENCED_ABSENT"),
            ("after_permission", 82, "FENCED_ABSENT"),
            ("after_file_before_core_commit", 83, "RECONCILED_POSTCONDITION"),
            ("before_outer_outcome", 84, "DELIVERED_RECEIPT"),
        ]
        for mode, exitcode, expected in variants:
            with self.subTest(mode=mode):
                root, policy, config, gate, _ = self.fixture(mode)
                process, _ = self.launch(root, policy, config, mode)
                process.join(20)
                self.assertEqual(process.exitcode, exitcode)
                reopened = ActionGate.open(root, policy, **config)
                recovered = reopened.recover()
                self.assertEqual(recovered["state"], expected)
                self.assertTrue(recovered["current_verified"])
                self.assertEqual(reopened.submit(config["content"])["reason"], "already_consumed")
                for _ in range(35):
                    self.assertTrue(reopened.recover()["current_verified"])
                target = policy.output_dir / "report.md"
                self.assertEqual(target.exists(), expected != "FENCED_ABSENT")
                if target.exists():
                    self.assertEqual(target.read_bytes(), config["content"].encode())
                self.assertEqual((policy.output_dir / "protected.txt").read_bytes(), b"unchanged")

    def test_inflight_revoke_is_never_acknowledged_as_cancellation(self):
        root, policy, config, gate, key = self.fixture("slow")
        revoke = decision_message(gate.request(), decision="revoke", issued_at=int(time.time()))
        signature = key.sign(canonical(revoke))
        entered, release = self.ctx.Event(), self.ctx.Event()
        process, results = self.launch(
            root, policy, config, "slow_delivery", entered=entered, release=release
        )
        self.assertTrue(entered.wait(10))
        try:
            with self.assertRaises(AuthorityBusy):
                gate.apply_decision(revoke, signature)
        finally:
            release.set()
        process.join(20)
        self.assertEqual(process.exitcode, 0)
        self.assertTrue(results.get(timeout=2)["applied"])
        observed = gate.apply_decision(revoke, signature)
        self.assertFalse(observed["accepted"])
        self.assertEqual(observed["reason"], "too_late_or_in_flight")

    def test_document_host_two_processes_admit_one_effect(self):
        host, _, content, target, protected = self.document_fixture("race")
        start = self.ctx.Event()
        first, one = self.launch_document(host.home, start=start)
        second, two = self.launch_document(host.home, start=start)
        start.set()
        first.join(20)
        second.join(20)
        self.assertEqual((first.exitcode, second.exitcode), (0, 0))
        observed = [one.get(timeout=2), two.get(timeout=2)]
        self.assertEqual(
            sorted((item["outcome"], item["reason"]) for item in observed),
            [("applied", "writer_receipt_recorded"), ("refused", "already_consumed")],
        )
        self.assertEqual(target.read_bytes(), content)
        self.assertEqual(protected.read_bytes(), b"unchanged")
        self.assertTrue(host.status(recover=True)["current_verified"])

    def test_document_host_child_crash_points_recover_without_replay(self):
        variants = (
            ("after_begin", 91, "FENCED_ABSENT"),
            ("after_permission", 92, "FENCED_ABSENT"),
            ("after_file_before_receipt", 93, "RECONCILED_POSTCONDITION"),
            ("before_outer_outcome", 94, "DELIVERED_RECEIPT"),
        )
        for mode, exitcode, expected in variants:
            with self.subTest(mode=mode):
                host, _, content, target, protected = self.document_fixture(mode)
                process, _ = self.launch_document(host.home, mode)
                process.join(20)
                self.assertEqual(process.exitcode, exitcode)
                reopened = DocumentHost.open(host.home)
                recovered = reopened.status(recover=True)
                self.assertEqual(recovered["state"], expected)
                self.assertTrue(recovered["current_verified"])
                before = target.stat() if target.exists() else None
                self.assertEqual(
                    reopened.execute_approved(),
                    {"outcome": "refused", "reason": "already_consumed"},
                )
                self.assertTrue(reopened.status(recover=True)["current_verified"])
                if expected == "FENCED_ABSENT":
                    self.assertFalse(target.exists())
                else:
                    self.assertEqual(target.read_bytes(), content)
                    after = target.stat()
                    self.assertEqual(
                        (after.st_dev, after.st_ino, after.st_mtime_ns),
                        (before.st_dev, before.st_ino, before.st_mtime_ns),
                    )
                self.assertEqual(protected.read_bytes(), b"unchanged")

    def test_document_host_inflight_revoke_never_acknowledges_cancellation(self):
        host, key, content, target, protected = self.document_fixture("slow")
        revoke = decision_message(host.request(), decision="revoke", issued_at=int(time.time()))
        detached = self.base / "revoke-slow.json"
        detached.write_bytes(canonical({
            "message": revoke,
            "signature_base64": base64.b64encode(key.sign(canonical(revoke))).decode("ascii"),
        }))
        entered, release = self.ctx.Event(), self.ctx.Event()
        process, results = self.launch_document(
            host.home, "slow_delivery", entered=entered, release=release
        )
        self.assertTrue(entered.wait(10))
        try:
            with self.assertRaises(AuthorityBusy):
                host.apply_decision(detached)
        finally:
            release.set()
        process.join(20)
        self.assertEqual(process.exitcode, 0)
        self.assertEqual(
            results.get(timeout=2), {"outcome": "applied", "reason": "writer_receipt_recorded"}
        )
        observed = host.apply_decision(detached)
        self.assertFalse(observed["accepted"])
        self.assertEqual(observed["reason"], "too_late_or_in_flight")
        self.assertEqual(target.read_bytes(), content)
        self.assertEqual(protected.read_bytes(), b"unchanged")
        self.assertTrue(host.status(recover=True)["current_verified"])


if __name__ == "__main__":
    unittest.main()
