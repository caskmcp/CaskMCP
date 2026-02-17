"""Approval and gate command registration for the top-level CLI."""

from __future__ import annotations

from collections.abc import Callable

import click

from caskmcp.utils.state import resolve_root


def register_approval_commands(
    *,
    cli: click.Group,
    run_with_lock: Callable[..., None],
) -> None:
    """Register approval/gate command groups on the provided CLI group."""

    @cli.group(hidden=True)
    def approve() -> None:
        """Alias group for `gate` (compatibility)."""

    @approve.command("sync")
    @click.option(
        "--tools", "-t",
        required=True,
        type=click.Path(exists=True),
        help="Path to tools.json manifest",
    )
    @click.option(
        "--policy",
        type=click.Path(exists=True),
        help="Path to policy.yaml artifact (defaults to sibling of --tools if present)",
    )
    @click.option(
        "--toolsets",
        type=click.Path(exists=True),
        help="Path to toolsets.yaml artifact (optional)",
    )
    @click.option(
        "--lockfile", "-l",
        type=click.Path(),
        help="Path to lockfile (default: ./caskmcp.lock.yaml)",
    )
    @click.option(
        "--capture-id",
        help="Capture ID to associate with this sync",
    )
    @click.option(
        "--scope",
        help="Scope name to associate with this sync",
    )
    @click.option(
        "--deterministic/--volatile-metadata",
        default=True,
        show_default=True,
        help="Deterministic lockfile metadata by default; use --volatile-metadata for ephemeral timestamps",
    )
    @click.option(
        "--prune-removed/--keep-removed",
        default=False,
        show_default=True,
        help="Remove tools no longer present in the manifest from the lockfile",
    )
    @click.pass_context
    def approve_sync(
        ctx: click.Context,
        tools: str,
        policy: str | None,
        toolsets: str | None,
        lockfile: str | None,
        capture_id: str | None,
        scope: str | None,
        deterministic: bool,
        prune_removed: bool,
    ) -> None:
        """Sync lockfile with a tools manifest.

        Compares the manifest against the lockfile and tracks changes:
        - New tools are added as pending approval
        - Modified tools require re-approval
        - Removed tools are tracked but not deleted

        \b
        Examples:
          caskmcp approve sync --tools tools.json
          caskmcp approve sync --tools tools.json --lockfile custom.lock.yaml
        """
        from caskmcp.cli.approve import run_approve_sync

        run_with_lock(
            ctx,
            "approve sync",
            lambda: run_approve_sync(
                tools_path=tools,
                policy_path=policy,
                toolsets_path=toolsets,
                lockfile_path=lockfile,
                capture_id=capture_id,
                scope=scope,
                verbose=ctx.obj.get("verbose", False),
                prune_removed=prune_removed,
                deterministic=deterministic,
            ),
        )

    @approve.command("list")
    @click.option(
        "--lockfile", "-l",
        type=click.Path(),
        help="Path to lockfile (default: ./caskmcp.lock.yaml)",
    )
    @click.option(
        "--status", "-s",
        type=click.Choice(["pending", "approved", "rejected"]),
        help="Filter by approval status",
    )
    @click.pass_context
    def approve_list(
        ctx: click.Context,
        lockfile: str | None,
        status: str | None,
    ) -> None:
        """List tool approvals from the lockfile.

        \b
        Examples:
          caskmcp approve list
          caskmcp approve list --status pending
          caskmcp approve list --status approved -v
        """
        from caskmcp.cli.approve import run_approve_list

        run_approve_list(
            lockfile_path=lockfile,
            status_filter=status,
            verbose=ctx.obj.get("verbose", False),
        )

    @approve.command("tool")
    @click.argument("tool_ids", nargs=-1)
    @click.option(
        "--lockfile", "-l",
        type=click.Path(),
        help="Path to lockfile (default: ./caskmcp.lock.yaml)",
    )
    @click.option(
        "--all", "all_pending",
        is_flag=True,
        help="Approve all pending tools",
    )
    @click.option(
        "--toolset",
        help="Approve tools within a specific toolset",
    )
    @click.option(
        "--by",
        "approved_by",
        help="Who is approving (default: $USER)",
    )
    @click.option(
        "--reason",
        help="Approval reason (recorded in lockfile signature metadata)",
    )
    @click.pass_context
    def approve_tool(
        ctx: click.Context,
        tool_ids: tuple[str, ...],
        lockfile: str | None,
        all_pending: bool,
        toolset: str | None,
        approved_by: str | None,
        reason: str | None,
    ) -> None:
        """Approve one or more tools.

        \b
        Examples:
          caskmcp approve tool get_users create_user
          caskmcp approve tool --all
          caskmcp approve tool get_users --by security@example.com
        """
        from caskmcp.cli.approve import run_approve_tool

        run_with_lock(
            ctx,
            "approve tool",
            lambda: run_approve_tool(
                tool_ids=tool_ids,
                lockfile_path=lockfile,
                all_pending=all_pending,
                toolset=toolset,
                approved_by=approved_by,
                reason=reason,
                root_path=str(ctx.obj.get("root", resolve_root())),
                verbose=ctx.obj.get("verbose", False),
            ),
        )

    @approve.command("reject")
    @click.argument("tool_ids", nargs=-1, required=True)
    @click.option(
        "--lockfile", "-l",
        type=click.Path(),
        help="Path to lockfile (default: ./caskmcp.lock.yaml)",
    )
    @click.option(
        "--reason", "-r",
        help="Reason for rejection",
    )
    @click.pass_context
    def approve_reject(
        ctx: click.Context,
        tool_ids: tuple[str, ...],
        lockfile: str | None,
        reason: str | None,
    ) -> None:
        """Reject one or more tools.

        Rejected tools will cause CI checks to fail.

        \b
        Examples:
          caskmcp approve reject delete_all_users --reason "Too dangerous"
          caskmcp approve reject tool1 tool2
        """
        from caskmcp.cli.approve import run_approve_reject

        run_with_lock(
            ctx,
            "approve reject",
            lambda: run_approve_reject(
                tool_ids=tool_ids,
                lockfile_path=lockfile,
                reason=reason,
                verbose=ctx.obj.get("verbose", False),
            ),
        )

    @approve.command("check")
    @click.option(
        "--lockfile", "-l",
        type=click.Path(),
        help="Path to lockfile (default: ./caskmcp.lock.yaml)",
    )
    @click.option(
        "--toolset",
        help="Check approval status for a specific toolset only",
    )
    @click.pass_context
    def approve_check(
        ctx: click.Context,
        lockfile: str | None,
        toolset: str | None,
    ) -> None:
        """Check if all tools are approved (for CI).

        Exit codes:
          0 - All tools approved
          1 - Pending or rejected tools exist
          2 - No lockfile found

        \b
        Examples:
          caskmcp approve check
          caskmcp approve check --lockfile custom.lock.yaml
        """
        from caskmcp.cli.approve import run_approve_check

        run_approve_check(
            lockfile_path=lockfile,
            toolset=toolset,
            verbose=ctx.obj.get("verbose", False),
        )

    @approve.command("snapshot")
    @click.option(
        "--lockfile", "-l",
        type=click.Path(),
        help="Path to lockfile (default: ./caskmcp.lock.yaml)",
    )
    @click.pass_context
    def approve_snapshot(ctx: click.Context, lockfile: str | None) -> None:
        """Materialize a baseline snapshot for an approved lockfile."""
        from caskmcp.cli.approve import run_approve_snapshot

        run_with_lock(
            ctx,
            "approve snapshot",
            lambda: run_approve_snapshot(
                lockfile_path=lockfile,
                root_path=str(ctx.obj.get("root", resolve_root())),
                verbose=ctx.obj.get("verbose", False),
            ),
        )

    @approve.command("resign")
    @click.option(
        "--lockfile", "-l",
        type=click.Path(),
        help="Path to lockfile (default: ./caskmcp.lock.yaml)",
    )
    @click.option("--toolset", help="Re-sign approvals for tools within a specific toolset only")
    @click.pass_context
    def approve_resign(ctx: click.Context, lockfile: str | None, toolset: str | None) -> None:
        """Re-sign existing approval signatures (migration / repair helper)."""
        from caskmcp.cli.approve import run_approve_resign

        run_with_lock(
            ctx,
            "approve resign",
            lambda: run_approve_resign(
                lockfile_path=lockfile,
                toolset=toolset,
                root_path=str(ctx.obj.get("root", resolve_root())),
                verbose=ctx.obj.get("verbose", False),
            ),
        )

    @cli.group()
    def gate() -> None:
        """Human approval workflow (canonical governance commands)."""

    @gate.command("sync")
    @click.option(
        "--tools", "-t",
        required=True,
        type=click.Path(exists=True),
        help="Path to tools.json manifest",
    )
    @click.option("--policy", type=click.Path(exists=True), help="Path to policy.yaml artifact")
    @click.option("--toolsets", type=click.Path(exists=True), help="Path to toolsets.yaml artifact")
    @click.option("--lockfile", "-l", type=click.Path(), help="Path to lockfile")
    @click.option("--capture-id", help="Capture ID to associate with this sync")
    @click.option("--scope", help="Scope name to associate with this sync")
    @click.option(
        "--deterministic/--volatile-metadata",
        default=True,
        show_default=True,
        help="Deterministic lockfile metadata by default",
    )
    @click.option(
        "--prune-removed/--keep-removed",
        default=False,
        show_default=True,
        help="Remove tools no longer present in the manifest from the lockfile",
    )
    @click.pass_context
    def gate_sync(
        ctx: click.Context,
        tools: str,
        policy: str | None,
        toolsets: str | None,
        lockfile: str | None,
        capture_id: str | None,
        scope: str | None,
        deterministic: bool,
        prune_removed: bool,
    ) -> None:
        """Alias for `caskmcp approve sync`."""
        ctx.invoke(
            approve_sync,
            tools=tools,
            policy=policy,
            toolsets=toolsets,
            lockfile=lockfile,
            capture_id=capture_id,
            scope=scope,
            deterministic=deterministic,
            prune_removed=prune_removed,
        )

    @gate.command("status")
    @click.option("--lockfile", "-l", type=click.Path(), help="Path to lockfile")
    @click.option(
        "--status",
        "status_filter",
        type=click.Choice(["pending", "approved", "rejected"]),
        help="Filter by approval status",
    )
    @click.pass_context
    def gate_status(
        ctx: click.Context,
        lockfile: str | None,
        status_filter: str | None,
    ) -> None:
        """Alias for `caskmcp approve list`."""
        ctx.invoke(approve_list, lockfile=lockfile, status=status_filter)

    @gate.command("allow")
    @click.argument("tool_ids", nargs=-1)
    @click.option("--lockfile", "-l", type=click.Path(), help="Path to lockfile")
    @click.option("--all", "all_pending", is_flag=True, help="Approve all pending tools")
    @click.option("--toolset", help="Approve tools within a specific toolset")
    @click.option("--by", "approved_by", help="Who is approving")
    @click.option("--reason", help="Approval reason")
    @click.pass_context
    def gate_allow(
        ctx: click.Context,
        tool_ids: tuple[str, ...],
        lockfile: str | None,
        all_pending: bool,
        toolset: str | None,
        approved_by: str | None,
        reason: str | None,
    ) -> None:
        """Alias for `caskmcp approve tool`."""
        ctx.invoke(
            approve_tool,
            tool_ids=tool_ids,
            lockfile=lockfile,
            all_pending=all_pending,
            toolset=toolset,
            approved_by=approved_by,
            reason=reason,
        )

    @gate.command("block")
    @click.argument("tool_ids", nargs=-1, required=True)
    @click.option("--lockfile", "-l", type=click.Path(), help="Path to lockfile")
    @click.option("--reason", "-r", help="Reason for rejection")
    @click.pass_context
    def gate_block(
        ctx: click.Context,
        tool_ids: tuple[str, ...],
        lockfile: str | None,
        reason: str | None,
    ) -> None:
        """Alias for `caskmcp approve reject`."""
        ctx.invoke(approve_reject, tool_ids=tool_ids, lockfile=lockfile, reason=reason)

    @gate.command("check")
    @click.option("--lockfile", "-l", type=click.Path(), help="Path to lockfile")
    @click.option("--toolset", help="Check approval status for a specific toolset")
    @click.pass_context
    def gate_check(
        ctx: click.Context,
        lockfile: str | None,
        toolset: str | None,
    ) -> None:
        """Alias for `caskmcp approve check`."""
        ctx.invoke(approve_check, lockfile=lockfile, toolset=toolset)

    @gate.command("snapshot")
    @click.option("--lockfile", "-l", type=click.Path(), help="Path to lockfile")
    @click.pass_context
    def gate_snapshot(ctx: click.Context, lockfile: str | None) -> None:
        """Alias for `caskmcp approve snapshot`."""
        ctx.invoke(approve_snapshot, lockfile=lockfile)

    @gate.command("resign")
    @click.option("--lockfile", "-l", type=click.Path(), help="Path to lockfile")
    @click.option("--toolset", help="Re-sign approvals for tools within a specific toolset only")
    @click.pass_context
    def gate_resign(
        ctx: click.Context,
        lockfile: str | None,
        toolset: str | None,
    ) -> None:
        """Alias for `caskmcp approve resign`."""
        ctx.invoke(approve_resign, lockfile=lockfile, toolset=toolset)
