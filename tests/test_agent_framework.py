"""Offline contract tests for the optional Agent Framework document integration.

Synthetic signing below is a test fixture, never an operator-review substitute.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import sqlite3
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from agent_framework import (
    Agent,
    BaseChatClient,
    ChatResponse,
    Content,
    FileCheckpointStorage,
    FunctionInvocationLayer,
    Message,
    WorkflowBuilder,
    WorkflowEvent,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ash_action_authority import (
    ActionCore,
    AuthorityError,
    DocumentHost,
    canonical,
    decision_message,
)
from ash_action_authority.agent_framework import (
    AgentFrameworkDocument,
    declaration_only_document_tool,
)


def pending_event(
    content: str = "Café — reviewed\r\n第二行.\r\n",
    *,
    request_id: str = "request-1",
    source_executor_id: str = "writer-agent",
    call_id: str = "call-1",
    arguments: str | dict[str, object] | None = None,
    name: str = "write_reviewed_document",
) -> WorkflowEvent:
    call = Content.from_function_call(
        call_id,
        name,
        arguments={"content": content} if arguments is None else arguments,
    )
    call.user_input_request = True
    return WorkflowEvent.request_info(request_id, source_executor_id, call, Content)


def _result(content: Content) -> dict[str, object]:
    """SDK Content normalizes a mapping result to its JSON wire representation."""
    return json.loads(content.result)


class _ScriptedChat(FunctionInvocationLayer, BaseChatClient):
    """Two offline outputs: one declaration-only call, then a plain completion."""

    def __init__(self, content: str, *, resume_only: bool = False) -> None:
        super().__init__()
        self.content = content
        self.calls = 0
        self.resume_only = resume_only
        self.resumed_messages: tuple[Message, ...] = ()

    async def _inner_get_response(self, *, messages, stream, options, **kwargs):
        if stream:
            raise AssertionError("streaming not used by this fixture")
        self.calls += 1
        if self.calls == 1 and not self.resume_only:
            return ChatResponse(
                messages=Message(
                    "assistant",
                    [
                        Content.from_function_call(
                            "call-1", "write_reviewed_document", arguments={"content": self.content}
                        )
                    ],
                )
            )
        self.resumed_messages = tuple(messages)
        if self.resume_only and not any(
            item.type == "function_result" and item.call_id == "call-1"
            for message in messages
            for item in message.contents
        ):
            raise AssertionError("checkpoint resumed without the original function result")
        return ChatResponse(messages=Message("assistant", [Content.from_text("Done.")]))


class AgentFrameworkDocumentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.home = self.root / "task"
        self.target = self.home / "output" / "document.md"
        self.content = "Café — reviewed\r\n第二行.\r\n"
        self.event = pending_event(self.content)
        self.signer = Ed25519PrivateKey.from_private_bytes(b"\x73" * 32)
        public_bytes = self.signer.public_key().public_bytes_raw()
        self.public = self.root / "synthetic-operator.hex"
        self.public.write_text(public_bytes.hex() + "\n", encoding="ascii")
        self.fingerprint = hashlib.sha256(public_bytes).hexdigest()
        self.decision_count = 0

    def prepare(self, event=None, **changes):
        options = {
            "workflow_id": "workflow-1",
            "public_key": self.public,
            "expected_key_fingerprint": self.fingerprint,
            "host_repository": "example/framework-document",
            "host_revision": "a" * 40,
            "allow_local_source_use": True,
        }
        options.update(changes)
        return AgentFrameworkDocument.prepare(
            self.home, self.event if event is None else event, **options
        )

    def decide(self, integration, decision="approve"):
        request = integration.host.request()
        message = decision_message(request, decision=decision, issued_at=int(time.time()))
        signature = self.signer.sign(canonical(message))
        self.decision_count += 1
        path = self.root / f"decision-{self.decision_count}.json"
        path.write_bytes(
            canonical(
                {
                    "message": message,
                    "signature_base64": base64.b64encode(signature).decode("ascii"),
                }
            )
        )
        return integration.host.apply_decision(path)

    def approve(self, integration):
        accepted = self.decide(integration)
        self.assertTrue(accepted["accepted"])
        self.assertFalse(self.target.exists())

    def response(self, integration, event=None, **changes):
        return integration.execute(
            self.event if event is None else event,
            workflow_id=changes.get("workflow_id", "workflow-1"),
        )

    def test_declaration_is_content_only_and_has_no_callable(self):
        tool = declaration_only_document_tool()
        self.assertEqual(tool.name, "write_reviewed_document")
        self.assertIsNone(tool.func)
        self.assertTrue(tool.declaration_only)
        self.assertEqual(set(tool.parameters()["properties"]), {"content"})
        self.assertEqual(tool.parameters()["required"], ["content"])
        self.assertFalse(tool.parameters()["additionalProperties"])

    def test_preapproval_refuses_then_signed_exact_bytes_apply_once(self):
        integration = self.prepare()
        self.assertEqual(
            set(integration.binding),
            {
                "schema",
                "workflow_id",
                "request_id",
                "source_executor_id",
                "call_id",
                "tool_name",
                "content_sha256",
            },
        )
        before = integration.host.status()["control_events"]
        response = self.response(integration)[self.event.request_id]
        self.assertEqual(_result(response), {"outcome": "refused", "reason": "not_approved"})
        self.assertEqual(integration.host.status()["control_events"], before)
        self.approve(integration)
        reopened = AgentFrameworkDocument.open(self.home)
        self.assertEqual(reopened.binding, integration.binding)
        response = self.response(reopened)[self.event.request_id]
        self.assertEqual(response.type, "function_result")
        self.assertEqual(response.call_id, "call-1")
        self.assertEqual(
            _result(response), {"outcome": "applied", "reason": "writer_receipt_recorded"}
        )
        self.assertEqual(self.target.read_bytes(), self.content.encode("utf-8"))
        before = self.target.stat()
        replay = self.response(AgentFrameworkDocument.open(self.home))[self.event.request_id]
        self.assertEqual(_result(replay), {"outcome": "refused", "reason": "already_consumed"})
        after = self.target.stat()
        self.assertEqual(
            (after.st_dev, after.st_ino, after.st_mtime_ns),
            (before.st_dev, before.st_ino, before.st_mtime_ns),
        )

    def test_changed_call_identity_and_content_do_not_spend(self):
        integration = self.prepare()
        self.approve(integration)
        cases = (
            pending_event(self.content + "altered"),
            pending_event(self.content, request_id="request-2"),
            pending_event(self.content, source_executor_id="other-agent"),
            pending_event(self.content, call_id="call-2"),
            pending_event(self.content, name="other-tool"),
            pending_event(arguments={"content": self.content, "approve": True}),
            pending_event(arguments='{"content":"one","content":"two"}'),
        )
        before = integration.host.status()["control_events"]
        for event in cases:
            with self.subTest(event=event):
                with self.assertRaisesRegex(AuthorityError, "framework_call_changed"):
                    self.response(integration, event)
                self.assertFalse(self.target.exists())
        with self.assertRaisesRegex(AuthorityError, "framework_call_changed"):
            self.response(integration, workflow_id="other-workflow")
        self.assertEqual(integration.host.status()["control_events"], before)
        self.assertEqual(
            _result(self.response(integration)[self.event.request_id])["outcome"], "applied"
        )

    def test_prepare_rejects_duplicate_json_and_authority_fields(self):
        invalid = (
            '{"content":"one","content":"two"}',
            '{"content":"one","path":"output/other.md"}',
            '{"content":"one","approve":true}',
            '{"content":NaN}',
            '{"content":""}',
            {"content": self.content, "approval": "yes"},
        )
        for arguments in invalid:
            with self.subTest(arguments=arguments):
                with self.assertRaises((AuthorityError, ValueError, TypeError)):
                    self.prepare(pending_event(arguments=arguments))
                self.assertFalse(self.home.exists())
        with self.assertRaises((AuthorityError, ValueError, TypeError)):
            self.prepare(pending_event(content="x" * 65537))
        self.assertFalse(self.home.exists())

    def test_prepare_requires_native_pending_function_call_marker(self):
        call = Content.from_function_call(
            "call-1", "write_reviewed_document", arguments={"content": self.content}
        )
        unmarked = WorkflowEvent.request_info("request-1", "writer-agent", call, Content)
        wrong_type = WorkflowEvent("output", call)
        for event in (unmarked, wrong_type, pending_event(name="other-tool")):
            with self.subTest(event_type=event.type):
                with self.assertRaisesRegex(AuthorityError, "pending_declaration_required"):
                    self.prepare(event)
                self.assertFalse(self.home.exists())

    def test_tampered_retained_binding_or_document_never_delivers(self):
        for retained_name in ("source.txt", "document.txt"):
            with self.subTest(retained_name=retained_name):
                self.home = self.root / f"task-{retained_name}"
                self.target = self.home / "output" / "document.md"
                integration = self.prepare()
                self.approve(integration)
                (self.home / retained_name).write_bytes(b"altered retained input\n")
                with self.assertRaises(AuthorityError):
                    integration.execute(self.event, workflow_id="workflow-1")
                self.assertFalse(self.target.exists())

    def test_concurrent_exact_execute_spends_one_attempt(self):
        integration = self.prepare()
        self.approve(integration)

        def execute_once():
            return _result(
                AgentFrameworkDocument.open(self.home).execute(
                    self.event, workflow_id="workflow-1"
                )[self.event.request_id]
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _: execute_once(), range(2)))
        self.assertEqual(
            sorted((item["outcome"], item["reason"]) for item in results),
            [("applied", "writer_receipt_recorded"), ("refused", "already_consumed")],
        )
        self.assertEqual(self.target.read_bytes(), self.content.encode("utf-8"))

    def test_recovery_is_readback_only_and_uncertain_stays_uncertain(self):
        integration = self.prepare()
        self.approve(integration)
        with patch.object(
            DocumentHost, "execute_approved", side_effect=AssertionError("writer called")
        ):
            response = integration.recover_response(self.event, workflow_id="workflow-1")
        self.assertEqual(
            _result(response[self.event.request_id]),
            {"outcome": "uncertain", "reason": "host_recovery_required"},
        )
        self.assertFalse(self.target.exists())

    def test_revoke_and_expiry_prevent_effect(self):
        integration = self.prepare(valid_seconds=60)
        self.approve(integration)
        revoked = self.decide(integration, "revoke")
        self.assertEqual(revoked["reason"], "revoked_before_begin")
        self.assertEqual(
            _result(self.response(integration)[self.event.request_id]),
            {"outcome": "refused", "reason": "not_approved"},
        )
        self.assertFalse(self.target.exists())
        self.approve(integration)
        with patch.object(
            ActionCore, "_now", return_value=integration.host.request()["expires_at"]
        ):
            expired = self.response(integration)[self.event.request_id]
        self.assertEqual(_result(expired), {"outcome": "refused", "reason": "expired"})
        self.assertFalse(self.target.exists())

    def test_post_effect_failure_recovers_response_without_replay(self):
        integration = self.prepare()
        self.approve(integration)
        original_save = ActionCore._save

        def fail_outcome(core, state, *, kind=None, **kwargs):
            if kind == "outcome":
                raise sqlite3.OperationalError("synthetic_post_effect_save_failure")
            return original_save(core, state, kind=kind, **kwargs)

        with patch.object(ActionCore, "_save", fail_outcome):
            uncertain = self.response(integration)[self.event.request_id]
        self.assertEqual(
            _result(uncertain), {"outcome": "uncertain", "reason": "host_recovery_required"}
        )
        self.assertEqual(self.target.read_bytes(), self.content.encode("utf-8"))
        before = self.target.stat()
        recovered = AgentFrameworkDocument.open(self.home).recover_response(
            self.event, workflow_id="workflow-1"
        )[self.event.request_id]
        self.assertEqual(
            _result(recovered),
            {"outcome": "applied", "reason": "verified_existing_effect", "recovered": True},
        )
        self.assertEqual(self.target.read_bytes(), self.content.encode("utf-8"))
        after = self.target.stat()
        self.assertEqual(
            (after.st_dev, after.st_ino, after.st_mtime_ns),
            (before.st_dev, before.st_ino, before.st_mtime_ns),
        )

    def test_recovery_before_effect_is_uncertain_and_cannot_deliver(self):
        integration = self.prepare()
        self.approve(integration)
        response = integration.recover_response(self.event, workflow_id="workflow-1")
        self.assertEqual(
            _result(response[self.event.request_id]),
            {"outcome": "uncertain", "reason": "host_recovery_required"},
        )
        self.assertFalse(self.target.exists())

    def test_native_agent_workflow_pause_approve_write_resume(self):
        async def journey():
            client = _ScriptedChat(self.content)
            agent = Agent(client, name="writer-agent", tools=[declaration_only_document_tool()])
            workflow = WorkflowBuilder(start_executor=agent).build()
            paused = await workflow.run("Draft one document")
            events = paused.get_request_info_events()
            self.assertEqual(len(events), 1)
            event = events[0]
            self.assertIsInstance(event, WorkflowEvent)
            self.assertEqual(event.type, "request_info")
            integration = self.prepare(event)
            self.approve(integration)
            response = integration.execute(event, workflow_id="workflow-1")
            self.assertEqual(_result(response[event.request_id])["outcome"], "applied")
            self.assertEqual(self.target.read_bytes(), self.content.encode("utf-8"))
            before = self.target.stat()
            completed = await workflow.run(responses=response)
            self.assertEqual(completed.get_request_info_events(), [])
            self.assertEqual(client.calls, 2)
            self.assertTrue(
                any(
                    item.type == "function_result" and item.call_id == "call-1"
                    for message in client.resumed_messages
                    for item in message.contents
                )
            )
            after = self.target.stat()
            self.assertEqual(
                (after.st_dev, after.st_ino, after.st_mtime_ns),
                (before.st_dev, before.st_ino, before.st_mtime_ns),
            )

        asyncio.run(journey())

    def test_failed_framework_resume_recovers_existing_effect_without_rewrite(self):
        async def journey():
            client = _ScriptedChat(self.content)
            agent = Agent(client, name="writer-agent", tools=[declaration_only_document_tool()])
            workflow = WorkflowBuilder(start_executor=agent).build()
            paused = await workflow.run("Draft one document")
            (event,) = paused.get_request_info_events()
            integration = self.prepare(event)
            self.approve(integration)
            delivered = integration.execute(event, workflow_id="workflow-1")
            self.assertEqual(_result(delivered[event.request_id])["outcome"], "applied")
            before = self.target.stat()

            # A bad host routing attempt fails before acknowledging this pending ID.
            with self.assertRaises((ValueError, RuntimeError, KeyError)):
                await workflow.run(responses={"wrong-request-id": delivered[event.request_id]})

            recovered = AgentFrameworkDocument.open(self.home).recover_response(
                event, workflow_id="workflow-1"
            )
            self.assertEqual(
                _result(recovered[event.request_id]),
                {"outcome": "applied", "reason": "verified_existing_effect", "recovered": True},
            )
            await workflow.run(responses=recovered)
            self.assertEqual(client.calls, 2)
            after = self.target.stat()
            self.assertEqual(
                (after.st_dev, after.st_ino, after.st_mtime_ns),
                (before.st_dev, before.st_ino, before.st_mtime_ns),
            )

        asyncio.run(journey())

    def test_new_workflow_instance_resumes_checkpoint_after_lost_response(self):
        async def journey():
            checkpoint_path = self.root / "checkpoints"
            storage = FileCheckpointStorage(checkpoint_path)
            first_client = _ScriptedChat(self.content)
            first_agent = Agent(
                first_client, name="writer-agent", tools=[declaration_only_document_tool()]
            )
            first_workflow = WorkflowBuilder(
                name="offline-document-workflow",
                start_executor=first_agent,
                checkpoint_storage=storage,
            ).build()
            paused = await first_workflow.run("Draft one document")
            (event,) = paused.get_request_info_events()
            checkpoint_id = first_workflow.get_last_checkpoint_id()
            self.assertIsInstance(checkpoint_id, str)
            integration = self.prepare(event)
            self.approve(integration)
            applied = integration.execute(event, workflow_id="workflow-1")
            self.assertEqual(_result(applied[event.request_id])["outcome"], "applied")
            before = self.target.stat()
            # Simulate a lost host-to-workflow response: discard the original workflow.
            del first_workflow
            del first_agent
            second_client = _ScriptedChat(self.content, resume_only=True)
            second_agent = Agent(
                second_client, name="writer-agent", tools=[declaration_only_document_tool()]
            )
            second_workflow = WorkflowBuilder(
                name="offline-document-workflow",
                start_executor=second_agent,
                checkpoint_storage=FileCheckpointStorage(checkpoint_path),
            ).build()
            recovered = AgentFrameworkDocument.open(self.home).recover_response(
                event, workflow_id="workflow-1"
            )
            self.assertEqual(_result(recovered[event.request_id])["outcome"], "applied")
            resumed = await second_workflow.run(
                checkpoint_id=checkpoint_id,
                responses=recovered,
            )
            self.assertEqual(resumed.get_request_info_events(), [])
            self.assertEqual(second_client.calls, 1)
            self.assertEqual(first_client.calls, 1)
            after = self.target.stat()
            self.assertEqual(
                (after.st_dev, after.st_ino, after.st_mtime_ns),
                (before.st_dev, before.st_ino, before.st_mtime_ns),
            )

        asyncio.run(journey())


if __name__ == "__main__":
    unittest.main()
