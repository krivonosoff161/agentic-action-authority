"""Compatibility example using the installed content-only tool router.

For persistent integration use ash_action_authority.DocumentHost.bind_tool().
Register only the descriptor/callback with the model, not the host or signer.
A Python callback is not a sandbox against arbitrary code or filesystem access.
"""

from ash_action_authority.dispatch import TOOL_NAME, make_dispatch, tool_descriptor

__all__ = ["TOOL_NAME", "make_dispatch", "tool_descriptor"]
