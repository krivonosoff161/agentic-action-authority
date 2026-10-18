"""Installed host integration for one reviewed public document.

Only the bound content callback belongs in a model's tool registry. This object,
its filesystem, enrollment and decision methods belong to the trusted host.
There is no signing capability or provider call here.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .dispatch import _make_dispatch, tool_descriptor
from .host import _restore, apply, setup
from .operator import _create_once
from .protocol import canonical


@dataclass(frozen=True)
class DocumentHost:
    """Persistent facade over the existing host and Harness writer, not a second engine."""

    home: Path

    @classmethod
    def prepare(
        cls,
        home: Path,
        *,
        public_key: Path,
        expected_key_fingerprint: str,
        source: Path,
        document: Path,
        host_repository: str,
        host_revision: str,
        valid_seconds: int = 3600,
        allow_local_source_use: bool = False,
    ) -> DocumentHost:
        """Prepare without executing. All paths and authority inputs are host-owned."""
        setup(
            home, public_key, source, document,
            expected_key_fingerprint=expected_key_fingerprint,
            host_repository=host_repository, host_revision=host_revision,
            valid_seconds=valid_seconds, allow_local_source_use=allow_local_source_use,
        )
        return cls(home.absolute())

    @classmethod
    def open(cls, home: Path) -> DocumentHost:
        """Reopen original host state; never recreate a missing or interrupted task."""
        _restore(home)
        return cls(home.absolute())

    @property
    def review_files(self) -> dict[str, Path]:
        """Initial request and exact content for the operator's trusted channel.

        After revocation export_request must write a fresh request to a new file.
        Paths do not themselves authenticate a transport or an operator.
        """
        return {"request": self.home / "request.json", "content": self.home / "document.txt"}

    def request(self) -> dict:
        return _restore(self.home).request()

    def export_request(self, destination: Path) -> None:
        """Create a fresh request file, never overwrite an earlier review artifact."""
        _create_once(destination, canonical(self.request()))

    def apply_decision(self, decision: Path) -> dict:
        """Host-only: verify an operator's decision without performing the effect."""
        return apply(self.home, decision)

    def status(self, *, recover: bool = False) -> dict:
        """Historical by default; recover performs readback/fencing, never delivery.

        Integrity-broken retained inputs can prevent reopening and readback.
        Preserve that task for manual inspection; never repair bytes to retry.
        """
        gate = _restore(self.home)
        return gate.recover() if recover else gate.status()

    @staticmethod
    def tool_descriptor() -> dict[str, Any]:
        return tool_descriptor()

    def bind_tool(self) -> Callable[[str, object], dict[str, str]]:
        """Content-only callback rechecking retained host inputs on each call.

        Invalid arguments are rejected before opening retained state. Unexpected
        failures require host recovery; this callback never retries. It does not
        isolate an agent with arbitrary Python/filesystem access.
        """
        def submit(content: str) -> dict:
            return _restore(self.home).submit(content)

        return _make_dispatch(submit)
