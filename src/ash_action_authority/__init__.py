"""Host-owned exact-action approval; Harness file effects are optional."""

from .core import ActionCore, AuthorityBusy, AuthorityError, EffectPort
from .protocol import ProtocolError, canonical, decision_message, request_digest


def __getattr__(name):
    if name == "DocumentHost":
        try:
            from .document import DocumentHost
        except ModuleNotFoundError as exc:
            if (exc.name == "agentic_security_harness"
                    or (exc.name or "").startswith("agentic_security_harness.")):
                raise ImportError("DocumentHost requires agentic-action-authority[harness]") from exc
            raise
        return DocumentHost
    if name == "ActionGate":
        try:
            from .engine import ActionGate
        except ModuleNotFoundError as exc:
            if (exc.name == "agentic_security_harness"
                    or (exc.name or "").startswith("agentic_security_harness.")):
                raise ImportError("ActionGate requires agentic-action-authority[harness]") from exc
            raise

        return ActionGate
    raise AttributeError(name)

__all__ = [
    "DocumentHost",
    "ActionGate",
    "ActionCore",
    "EffectPort",
    "AuthorityError",
    "AuthorityBusy",
    "ProtocolError",
    "canonical",
    "decision_message",
    "request_digest",
]
