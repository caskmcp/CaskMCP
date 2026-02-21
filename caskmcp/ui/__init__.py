"""Cask interactive TUI layer.

All TUI output goes to stderr. stdout is reserved for machine-readable output.
"""

from __future__ import annotations

from caskmcp.ui.console import err_console
from caskmcp.ui.policy import should_interact

__all__ = ["err_console", "should_interact"]
