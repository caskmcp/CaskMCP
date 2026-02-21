"""Interactive gate review flow for tool approval."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from caskmcp.ui.console import err_console
from caskmcp.ui.discovery import find_lockfiles
from caskmcp.ui.echo import echo_plan, echo_summary
from caskmcp.ui.prompts import confirm, confirm_typed, select_one
from caskmcp.ui.runner import (
    load_lockfile_tools,
    run_gate_approve,
    run_gate_reject,
)
from caskmcp.ui.tables import risk_summary_panel, tool_approval_table


def gate_review_flow(
    *,
    lockfile_path: str | None = None,
    root_path: str | None = None,
    verbose: bool = False,  # noqa: ARG001
    ctx: Any = None,  # noqa: ARG001
    missing_param: str | None = None,  # noqa: ARG001
) -> None:
    """Interactive tool review and approval flow.

    Safety invariants:
    - Never auto-approves without explicit confirmation.
    - High-risk/critical tools require per-tool typed confirmation.
    - Block decisions require a reason.
    """
    con = err_console
    root = Path(root_path) if root_path else Path(".caskmcp")

    # Resolve lockfile
    if lockfile_path is None:
        candidates = find_lockfiles(root)
        if not candidates:
            con.print("[error]No lockfiles found.[/error]")
            con.print("Run 'cask gate sync' first to create one.")
            return
        if len(candidates) == 1:
            lockfile_path = str(candidates[0])
        else:
            labels = [str(p) for p in candidates]
            lockfile_path = select_one(labels, prompt="Select lockfile", console=con)

    # Validate it's a file, not a directory
    lf_path = Path(lockfile_path)
    if lf_path.is_dir():
        con.print(f"[error]Expected a file, got a directory: {lockfile_path}[/error]")
        con.print("Provide the path to a .yaml lockfile, not a directory.")
        return

    # Load and display
    try:
        lockfile, all_tools = load_lockfile_tools(lockfile_path)
    except FileNotFoundError as exc:
        con.print(f"[error]{exc}[/error]")
        return

    from caskmcp.core.approval.lockfile import ApprovalStatus

    pending = [t for t in all_tools if t.status == ApprovalStatus.PENDING]

    if not pending:
        con.print("[success]No pending tools. All tools are reviewed.[/success]")
        return

    con.print()
    con.print(f"[heading]Gate Review[/heading] \u2014 {len(pending)} tools pending")
    con.print()

    table = tool_approval_table(pending)
    con.print(table)
    con.print()
    con.print(risk_summary_panel(pending))
    con.print()

    # Categorize by risk
    low_medium = [t for t in pending if t.risk_tier in ("low", "medium")]
    high_critical = [t for t in pending if t.risk_tier in ("high", "critical")]

    # Review options
    options = []
    labels = []
    if low_medium:
        options.append("approve_low_medium")
        labels.append(f"Approve all low/medium-risk ({len(low_medium)} tools)")
    options.append("one_by_one")
    labels.append("Review one by one")
    if pending:
        options.append("approve_all")
        labels.append(f"Approve all ({len(pending)} tools)")
    options.append("cancel")
    labels.append("Cancel")

    choice = select_one(options, labels=labels, prompt="Review mode", console=con)

    if choice == "cancel":
        return

    to_approve: list[str] = []
    to_block: list[tuple[str, str]] = []  # (tool_id, reason)

    if choice == "approve_low_medium":
        to_approve = [t.tool_id for t in low_medium]
        # High/critical still need individual review
        if high_critical:
            con.print(
                f"\n[warning]{len(high_critical)} high/critical-risk tools still need review:[/warning]"
            )
            for t in high_critical:
                _review_single_tool(t, to_approve, to_block, con)

    elif choice == "one_by_one":
        for t in pending:
            _review_single_tool(t, to_approve, to_block, con)

    elif choice == "approve_all":
        # Low/medium approved directly
        to_approve = [t.tool_id for t in low_medium]
        # High/critical require per-tool typed confirmation
        for t in high_critical:
            con.print(
                f"\n[risk.{t.risk_tier}]{t.risk_tier.upper()}[/risk.{t.risk_tier}] "
                f"[bold]{t.name}[/bold] \u2014 {t.method} {t.path}"
            )
            if confirm_typed(
                f"Approve {t.name}?",
                required_text="APPROVE",
                console=con,
            ):
                to_approve.append(t.tool_id)
            else:
                con.print(f"  [muted]Skipped {t.name}[/muted]")

    if not to_approve and not to_block:
        con.print("[muted]No changes made.[/muted]")
        return

    # Show plan
    commands: list[list[str]] = []
    if to_approve:
        commands.append(["cask", "gate", "allow", *to_approve, "--lockfile", lockfile_path])
    for tid, reason in to_block:
        commands.append(["cask", "gate", "block", tid, "--lockfile", lockfile_path, "--reason", reason])

    echo_plan(commands, console=con)

    if not confirm("Proceed with these changes?", default=True, console=con):
        return

    # Execute
    if to_approve:
        try:
            result = run_gate_approve(
                tool_ids=to_approve,
                lockfile_path=lockfile_path,
                root_path=str(root),
            )
            con.print(f"[success]Approved {len(result.approved_ids)} tools.[/success]")
        except Exception as exc:
            con.print(f"[error]Approval failed: {exc}[/error]")

    for tid, reason in to_block:
        try:
            run_gate_reject(
                tool_ids=[tid],
                lockfile_path=lockfile_path,
                reason=reason,
            )
            con.print(f"[error]Blocked {tid}: {reason}[/error]")
        except Exception as exc:
            con.print(f"[error]Block failed: {exc}[/error]")

    echo_summary(commands, console=con)


def _review_single_tool(
    tool: Any,
    to_approve: list[str],
    to_block: list[tuple[str, str]],
    con: Any,
) -> None:
    """Review a single tool interactively."""
    from caskmcp.ui.prompts import input_text

    risk_style = f"risk.{tool.risk_tier}" if tool.risk_tier in ("low", "medium", "high", "critical") else ""
    con.print(
        f"\n[{risk_style}]{tool.risk_tier.upper()}[/{risk_style}] "
        f"[bold]{tool.name}[/bold] \u2014 {tool.method} {tool.path} ({tool.host})"
    )
    if tool.toolsets:
        con.print(f"  Toolsets: {', '.join(tool.toolsets)}")

    action = select_one(
        ["approve", "block", "skip"],
        prompt=f"Action for {tool.name}",
        console=con,
    )

    if action == "approve":
        if tool.risk_tier in ("high", "critical"):
            if confirm_typed(
                f"Approve {tool.risk_tier}-risk tool {tool.name}?",
                required_text="APPROVE",
                console=con,
            ):
                to_approve.append(tool.tool_id)
            else:
                con.print(f"  [muted]Skipped {tool.name}[/muted]")
        else:
            to_approve.append(tool.tool_id)
    elif action == "block":
        reason = input_text("Reason for blocking", console=con)
        if not reason:
            reason = "Blocked during interactive review"
        to_block.append((tool.tool_id, reason))
