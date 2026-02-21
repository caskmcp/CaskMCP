"""Shared Rich Console and style definitions for the Cask TUI.

All interactive output goes to stderr via ``err_console``.
Flows never write to stdout.
"""

from __future__ import annotations

from rich.console import Console
from rich.theme import Theme

CASK_THEME = Theme(
    {
        "info": "cyan",
        "success": "bold green",
        "warning": "bold yellow",
        "error": "bold red",
        "risk.low": "green",
        "risk.medium": "yellow",
        "risk.high": "red",
        "risk.critical": "bold red",
        "heading": "bold cyan",
        "muted": "dim",
        "command": "bold white on dark_blue",
        "step.done": "bold green",
        "step.active": "bold cyan",
        "step.pending": "dim",
    }
)

# All TUI chrome goes to stderr.
err_console = Console(stderr=True, theme=CASK_THEME)
