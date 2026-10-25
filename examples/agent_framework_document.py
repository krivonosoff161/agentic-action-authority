"""Offline Agent Framework pause/review/resume sketch for a disposable document.

The fixed-key signature here is synthetic test data, NOT independent human review.
Real hosts must enroll an operator key outside the agent, present the exact request
and retained document to that operator, then import the detached decision.
No model, provider, network, credential, or external destination is used here.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import time
from pathlib import Path
from tempfile import TemporaryDirectory

from agent_framework import (
    Agent,
    BaseChatClient,
    ChatResponse,
    Content,
    FileCheckpointStorage,
    FunctionInvocationLayer,
    Message,
    WorkflowBuilder,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ash_action_authority import canonical, decision_message
from ash_action_authority.agent_framework import (
    AgentFrameworkDocument,
    declaration_only_document_tool,
)


class OfflineChat(FunctionInvocationLayer, BaseChatClient):
    """Scripted framework client; it neither calls nor simulates a provider API."""

    def __init__(self, *, resume_only: bool = False) -> None:
        super().__init__()
        self.calls = 0
        self.resume_only = resume_only

    async def _inner_get_response(self, *, messages, stream, options, **kwargs):
        assert not stream
        self.calls += 1
        if self.calls == 1 and not self.resume_only:
            return ChatResponse(
                messages=Message(
                    "assistant",
                    [
                        Content.from_function_call(
                            "call-1",
                            "write_reviewed_document",
                            arguments={"content": "Reviewed café\r\n第二行\r\n"},
                        )
                    ],
                )
            )
        if self.resume_only:
            assert any(
                item.type == "function_result" and item.call_id == "call-1"
                for message in messages
                for item in message.contents
            )
        return ChatResponse(messages=Message("assistant", [Content.from_text("Done.")]))


async def main() -> None:
    with TemporaryDirectory() as directory:
        root = Path(directory)
        home = root / "task"
        private = Ed25519PrivateKey.from_private_bytes(b"\x73" * 32)
        public_bytes = private.public_key().public_bytes_raw()
        public_path = root / "synthetic-public.hex"
        public_path.write_text(public_bytes.hex() + "\n", encoding="ascii")

        client = OfflineChat()
        agent = Agent(client, name="writer-agent", tools=[declaration_only_document_tool()])
        checkpoint_path = root / "checkpoints"
        workflow = WorkflowBuilder(
            name="offline-document-workflow",
            start_executor=agent,
            checkpoint_storage=FileCheckpointStorage(checkpoint_path),
        ).build()
        paused = await workflow.run("Draft the disposable document")
        pending = paused.get_request_info_events()
        assert len(pending) == 1
        event = pending[0]
        checkpoint_id = workflow.get_last_checkpoint_id()
        assert checkpoint_id is not None

        integration = AgentFrameworkDocument.prepare(
            home,
            event,
            workflow_id="offline-workflow",
            public_key=public_path,
            expected_key_fingerprint=hashlib.sha256(public_bytes).hexdigest(),
            host_repository="example/offline-framework-document",
            host_revision="a" * 40,
            allow_local_source_use=True,
        )
        # A real operator must inspect BOTH files independently before signing.
        request_file = integration.host.review_files["request"]
        document_file = integration.host.review_files["content"]
        assert request_file.exists() and document_file.exists()
        message = decision_message(
            integration.host.request(), decision="approve", issued_at=int(time.time())
        )
        detached = root / "synthetic-decision.json"
        detached.write_bytes(
            canonical(
                {
                    "message": message,
                    "signature_base64": base64.b64encode(private.sign(canonical(message))).decode(
                        "ascii"
                    ),
                }
            )
        )
        assert integration.host.apply_decision(detached)["accepted"]

        # The trusted host uses retained bytes; it never asks the model to repeat them.
        reopened = AgentFrameworkDocument.open(home)
        responses = reopened.execute(event, workflow_id="offline-workflow")
        assert json.loads(responses[event.request_id].result)["outcome"] == "applied"
        # A simulated lost framework response leaves the first workflow pending.
        # Recreate workflow from the SDK's on-disk checkpoint, recover readback,
        # then send only the original function result, never model-generated content.
        del workflow
        del agent
        resumed_client = OfflineChat(resume_only=True)
        resumed_agent = Agent(
            resumed_client, name="writer-agent", tools=[declaration_only_document_tool()]
        )
        resumed_workflow = WorkflowBuilder(
            name="offline-document-workflow",
            start_executor=resumed_agent,
            checkpoint_storage=FileCheckpointStorage(checkpoint_path),
        ).build()
        assert (
            home / "output" / "document.md"
        ).read_bytes() == "Reviewed café\r\n第二行\r\n".encode()
        recovered = AgentFrameworkDocument.open(home).recover_response(
            event, workflow_id="offline-workflow"
        )
        assert json.loads(recovered[event.request_id].result) == {
            "outcome": "applied",
            "reason": "verified_existing_effect",
            "recovered": True,
        }
        await resumed_workflow.run(checkpoint_id=checkpoint_id, responses=recovered)
        assert client.calls == 1 and resumed_client.calls == 1
        print(
            "Offline pause, synthetic approval, exact write, checkpoint resume, and readback passed."
        )


if __name__ == "__main__":
    asyncio.run(main())
