"""Reusable Rich table formatters for the Cask TUI."""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING

from rich.panel import Panel
from rich.table import Table

if TYPE_CHECKING:
    from caskmcp.core.approval.lockfile import ToolApproval

_STATUS_ICONS = {
    "approved": "[success]\u2713[/success]",
    "pending": "[warning]\u25cb[/warning]",
    "rejected": "[error]\u2717[/error]",
}

_RISK_STYLES = {
    "low": "risk.low",
    "medium": "risk.medium",
    "high": "risk.high",
    "critical": "risk.critical",
}


def tool_approval_table(
    tools: list[ToolApproval],
    *,
    show_signature: bool = False,
) -> Table:
    """Build a Rich Table showing tools with status, risk, method, and path."""
    table = Table(title="Tool Approvals", show_lines=False, pad_edge=False)
    table.add_column("", width=3)  # status icon
    table.add_column("Tool", style="bold")
    table.add_column("Risk")
    table.add_column("Method")
    table.add_column("Path")
    table.add_column("Host", style="muted")
    if show_signature:
        table.add_column("Signature", style="muted")

    for tool in sorted(tools, key=lambda t: (_risk_sort(t.risk_tier), t.name)):
        icon = _STATUS_ICONS.get(tool.status, "?")
        risk_style = _RISK_STYLES.get(tool.risk_tier, "")
        risk_text = f"[{risk_style}]{tool.risk_tier}[/{risk_style}]" if risk_style else tool.risk_tier
        row: list[str] = [
            icon,
            tool.name,
            risk_text,
            tool.method.upper(),
            tool.path,
            tool.host,
        ]
        if show_signature:
            sig = (tool.approval_signature or "")[:20]
            row.append(sig + "..." if len(tool.approval_signature or "") > 20 else sig)
        table.add_row(*row)

    return table


def doctor_checklist(
    checks: list[tuple[str, bool, str]],
) -> Table:
    """Build a checklist table: (label, passed, detail).

    Each row shows a green checkmark or red X, the check name, and detail.
    """
    table = Table(show_header=False, show_lines=False, pad_edge=False, box=None)
    table.add_column("", width=3)
    table.add_column("Check", style="bold")
    table.add_column("Detail")

    for label, passed, detail in checks:
        icon = "[success]\u2713[/success]" if passed else "[error]\u2717[/error]"
        style = "" if passed else "error"
        table.add_row(icon, f"[{style}]{label}[/{style}]" if style else label, detail)

    return table


def risk_summary_panel(tools: list[ToolApproval]) -> Panel:
    """Compact panel showing counts per risk tier."""
    counts: Counter[str] = Counter()
    for t in tools:
        counts[t.risk_tier] += 1

    parts: list[str] = []
    for tier in ("critical", "high", "medium", "low"):
        if counts[tier]:
            style = _RISK_STYLES.get(tier, "")
            parts.append(f"[{style}]{tier}: {counts[tier]}[/{style}]")

    body = "  ".join(parts) if parts else "[muted]no tools[/muted]"
    return Panel(body, title="Risk Summary", expand=False)


def _risk_sort(risk: str) -> int:
    """Sort key: critical first, low last."""
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(risk, 4)
