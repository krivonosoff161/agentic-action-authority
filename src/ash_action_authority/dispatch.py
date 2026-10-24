"""Content-only tool routing; this is not a Python or filesystem sandbox."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .engine import ActionGate

TOOL_NAME = "submit_approved_document"
_REFUSALS = frozenset(
    {"invalid_content", "object_changed", "already_consumed", "not_approved", "expired", "capacity"}
)


def tool_descriptor() -> dict[str, Any]:
    """Return a fresh descriptor with no path, key or approval arguments."""
    return {
        "name": TOOL_NAME,
        "description": "Submit the exact document text for a host-approved create-only action.",
        "parameters": {
            "type": "object",
            "properties": {"content": {"type": "string"}},
            "required": ["content"],
            "additionalProperties": False,
        },
    }


def _submit_outcome(submit: Callable[[], dict]) -> dict[str, str]:
    """Map one host submission to the public coarse outcome without retrying."""
    try:
        result = submit()
    except Exception:
        # Storage failure can follow an effect; never report no-effect or retry.
        return {"outcome": "uncertain", "reason": "host_recovery_required"}
    if type(result) is not dict:
        return {"outcome": "uncertain", "reason": "host_recovery_required"}
    if result.get("applied") is True and result.get("status") == "DELIVERED_RECEIPT":
        return {"outcome": "applied", "reason": "writer_receipt_recorded"}
    reason = result.get("reason")
    if result.get("applied") is False and type(reason) is str and reason in _REFUSALS:
        return {"outcome": "refused", "reason": reason}
    return {"outcome": "uncertain", "reason": "host_recovery_required"}


def _make_dispatch(submit: Callable[[str], dict]) -> Callable[[str, object], dict[str, str]]:
    def dispatch(name: str, arguments: object) -> dict[str, str]:
        if type(name) is not str or name != TOOL_NAME:
            return {"outcome": "refused", "reason": "unknown_tool"}
        if (
            type(arguments) is not dict
            or set(arguments) != {"content"}
            or type(arguments["content"]) is not str
        ):
            return {"outcome": "refused", "reason": "invalid_arguments"}
        return _submit_outcome(lambda: submit(arguments["content"]))

    return dispatch


def make_dispatch(gate: ActionGate) -> Callable[[str, object], dict[str, str]]:
    """Bind a host-owned gate. Expose only this callback to parsed model calls.

    The host owns construction, approval and recovery. Arbitrary code in the
    host process can inspect Python objects; a closure is not isolation.
    """
    if not isinstance(gate, ActionGate):
        raise TypeError("host_gate_required")
    return _make_dispatch(gate.submit)
