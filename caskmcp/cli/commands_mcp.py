"""MCP and serve command registration for the top-level CLI."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import click

from caskmcp.utils.state import confirmation_store_path, resolve_root


def register_mcp_commands(
    *,
    cli: click.Group,
    run_with_lock: Callable[..., None],
) -> None:
    """Register MCP-related commands on the provided CLI group."""

    @cli.command()
    @click.option(
        "--tools", "-t",
        type=click.Path(),
        help="Path to tools.json manifest",
    )
    @click.option(
        "--toolpack",
        type=click.Path(exists=True),
        help="Path to toolpack.yaml (resolves manifest/policy/toolsets paths)",
    )
    @click.option(
        "--toolsets",
        type=click.Path(),
        help="Path to toolsets.yaml (defaults to sibling of --tools if present)",
    )
    @click.option(
        "--toolset",
        help="Named toolset to expose (defaults to readonly when toolsets.yaml exists)",
    )
    @click.option(
        "--policy", "-p",
        type=click.Path(),
        help="Path to policy.yaml (optional)",
    )
    @click.option(
        "--lockfile", "-l",
        type=click.Path(),
        help="Path to approved lockfile (required by default unless --unsafe-no-lockfile)",
    )
    @click.option(
        "--base-url",
        help="Base URL for upstream API (overrides manifest hosts)",
    )
    @click.option(
        "--auth",
        "auth_header",
        help="Authorization header value for upstream requests",
    )
    @click.option(
        "--audit-log",
        type=click.Path(),
        help="Path for audit log file",
    )
    @click.option(
        "--dry-run",
        is_flag=True,
        help="Evaluate policy but don't execute upstream calls",
    )
    @click.option(
        "--confirm-store",
        type=click.Path(),
        help="Path to local out-of-band confirmation store",
    )
    @click.option(
        "--allow-private-cidr",
        "allow_private_cidrs",
        multiple=True,
        help="Allow private CIDR targets (repeatable; default denies private ranges)",
    )
    @click.option(
        "--allow-redirects",
        is_flag=True,
        help="Allow redirects (each hop is re-validated against allowlists)",
    )
    @click.option(
        "--unsafe-no-lockfile",
        is_flag=True,
        help="Allow runtime without approved lockfile (unsafe escape hatch)",
    )
    @click.pass_context
    def serve(
        ctx: click.Context,
        tools: str | None,
        toolpack: str | None,
        toolsets: str | None,
        toolset: str | None,
        policy: str | None,
        lockfile: str | None,
        base_url: str | None,
        auth_header: str | None,
        audit_log: str | None,
        dry_run: bool,
        confirm_store: str | None,
        allow_private_cidrs: tuple[str, ...],
        allow_redirects: bool,
        unsafe_no_lockfile: bool,
    ) -> None:
        """Alias for `caskmcp mcp serve`.

        This command exists for convenience and forwards to MCP server runtime.
        """
        click.echo(
            "Notice: `caskmcp serve` is an alias for `caskmcp mcp serve`.",
            err=True,
        )

        resolved_confirm_store = confirm_store or str(
            confirmation_store_path(ctx.obj.get("root", resolve_root()))
        )

        from caskmcp.cli.mcp import run_mcp_serve

        lock_id = None
        if toolpack:
            lock_id = f"toolpack:{Path(toolpack).resolve()}"
        elif tools:
            lock_id = f"tools:{Path(tools).resolve()}"

        run_with_lock(
            ctx,
            "serve",
            lambda: run_mcp_serve(
                tools_path=tools,
                toolpack_path=toolpack,
                toolsets_path=toolsets,
                toolset_name=toolset,
                policy_path=policy,
                lockfile_path=lockfile,
                base_url=base_url,
                auth_header=auth_header,
                audit_log=audit_log,
                dry_run=dry_run,
                confirmation_store_path=resolved_confirm_store,
                allow_private_cidrs=list(allow_private_cidrs),
                allow_redirects=allow_redirects,
                unsafe_no_lockfile=unsafe_no_lockfile,
                verbose=ctx.obj.get("verbose", False),
            ),
            lock_id=lock_id,
        )

    @cli.group()
    def mcp() -> None:
        """MCP server commands for exposing tools to AI agents.

        The MCP (Model Context Protocol) server exposes your compiled tools
        as callable actions that AI agents like Claude can use safely.
        """

    @mcp.command("serve")
    @click.option(
        "--tools", "-t",
        type=click.Path(),
        help="Path to tools.json manifest",
    )
    @click.option(
        "--toolpack",
        type=click.Path(exists=True),
        help="Path to toolpack.yaml (resolves manifest/policy/toolsets paths)",
    )
    @click.option(
        "--toolsets",
        type=click.Path(),
        help="Path to toolsets.yaml (defaults to sibling of --tools if present)",
    )
    @click.option(
        "--toolset",
        help="Named toolset to expose (defaults to readonly when toolsets.yaml exists)",
    )
    @click.option(
        "--policy", "-p",
        type=click.Path(),
        help="Path to policy.yaml (optional)",
    )
    @click.option(
        "--lockfile", "-l",
        type=click.Path(),
        help="Path to approved lockfile (required by default unless --unsafe-no-lockfile)",
    )
    @click.option(
        "--base-url",
        help="Base URL for upstream API (overrides manifest hosts)",
    )
    @click.option(
        "--auth",
        "auth_header",
        help="Authorization header value for upstream requests",
    )
    @click.option(
        "--audit-log",
        type=click.Path(),
        help="Path for audit log file",
    )
    @click.option(
        "--dry-run",
        is_flag=True,
        help="Evaluate policy but don't execute upstream calls",
    )
    @click.option(
        "--confirm-store",
        type=click.Path(),
        help="Path to local out-of-band confirmation store",
    )
    @click.option(
        "--allow-private-cidr",
        "allow_private_cidrs",
        multiple=True,
        help="Allow private CIDR targets (repeatable; default denies private ranges)",
    )
    @click.option(
        "--allow-redirects",
        is_flag=True,
        help="Allow redirects (each hop is re-validated against allowlists)",
    )
    @click.option(
        "--unsafe-no-lockfile",
        is_flag=True,
        help="Allow runtime without approved lockfile (unsafe escape hatch)",
    )
    @click.pass_context
    def mcp_serve(
        ctx: click.Context,
        tools: str | None,
        toolpack: str | None,
        toolsets: str | None,
        toolset: str | None,
        policy: str | None,
        lockfile: str | None,
        base_url: str | None,
        auth_header: str | None,
        audit_log: str | None,
        dry_run: bool,
        confirm_store: str | None,
        allow_private_cidrs: tuple[str, ...],
        allow_redirects: bool,
        unsafe_no_lockfile: bool,
    ) -> None:
        """Start an MCP server exposing tools from a compiled manifest.

        The server runs on stdio transport, suitable for use with Claude Desktop
        or other MCP clients. Tools are exposed with policy enforcement,
        confirmation requirements, and audit logging.

        \b
        Examples:
          # Basic usage
          caskmcp mcp serve --tools .caskmcp/artifacts/*/tools.json

          # Resolve all paths from a toolpack
          caskmcp mcp serve --toolpack .caskmcp/toolpacks/<toolpack-id>/toolpack.yaml

          # Expose a specific curated toolset
          caskmcp mcp serve --tools tools.json --toolsets toolsets.yaml --toolset readonly

          # With policy enforcement
          caskmcp mcp serve --tools tools.json --policy policy.yaml

          # With lockfile approval enforcement
          caskmcp mcp serve --tools tools.json --lockfile caskmcp.lock.yaml

          # With upstream API configuration
          caskmcp mcp serve --tools tools.json --base-url https://api.example.com --auth "Bearer token123"

          # Dry run mode (no actual API calls)
          caskmcp mcp serve --tools tools.json --dry-run

        \b
        Claude Desktop configuration (~/.claude/claude_desktop_config.json):
          {
            "mcpServers": {
              "my-api": {
                "command": "caskmcp",
                "args": ["mcp", "serve", "--toolpack", "/path/to/toolpack.yaml"]
              }
            }
          }
        """
        resolved_confirm_store = confirm_store or str(
            confirmation_store_path(ctx.obj.get("root", resolve_root()))
        )

        from caskmcp.cli.mcp import run_mcp_serve

        lock_id = None
        if toolpack:
            lock_id = f"toolpack:{Path(toolpack).resolve()}"
        elif tools:
            lock_id = f"tools:{Path(tools).resolve()}"

        run_with_lock(
            ctx,
            "mcp serve",
            lambda: run_mcp_serve(
                tools_path=tools,
                toolpack_path=toolpack,
                toolsets_path=toolsets,
                toolset_name=toolset,
                policy_path=policy,
                lockfile_path=lockfile,
                base_url=base_url,
                auth_header=auth_header,
                audit_log=audit_log,
                dry_run=dry_run,
                confirmation_store_path=resolved_confirm_store,
                allow_private_cidrs=list(allow_private_cidrs),
                allow_redirects=allow_redirects,
                unsafe_no_lockfile=unsafe_no_lockfile,
                verbose=ctx.obj.get("verbose", False),
            ),
            lock_id=lock_id,
        )

    @mcp.command("inspect")
    @click.option(
        "--artifacts", "-a",
        type=click.Path(exists=True),
        help="Path to artifacts directory",
    )
    @click.option(
        "--tools", "-t",
        type=click.Path(exists=True),
        help="Path to tools.json (overrides --artifacts)",
    )
    @click.option(
        "--policy", "-p",
        type=click.Path(exists=True),
        help="Path to policy.yaml (overrides --artifacts)",
    )
    @click.option(
        "--lockfile", "-l",
        type=click.Path(),
        help="Path to lockfile (default: ./caskmcp.lock.yaml)",
    )
    @click.pass_context
    def mcp_meta(
        ctx: click.Context,  # noqa: ARG001
        artifacts: str | None,
        tools: str | None,
        policy: str | None,
        lockfile: str | None,
    ) -> None:
        """Start an inspect MCP server exposing read-only governance introspection.

        This server allows operators and CI tools to inspect CaskMCP capability state:
        - List and inspect available actions
        - Check if actions would be allowed by policy
        - View approval status of tools
        - Get risk summaries

        This server is read-only and does not expose approval mutation APIs.

        \b
        Examples:
          # With artifacts directory
          caskmcp mcp inspect --artifacts .caskmcp/artifacts/*/

          # With explicit paths
          caskmcp mcp inspect --tools tools.json --policy policy.yaml

        \b
        Available tools exposed:
          - caskmcp_list_actions: List all actions with filtering
          - caskmcp_check_policy: Check if action allowed by policy
          - caskmcp_get_approval_status: Get approval status
          - caskmcp_list_pending_approvals: List pending approvals
          - caskmcp_get_action_details: Get detailed action info
          - caskmcp_risk_summary: Get risk tier breakdown

        \b
        Claude Desktop configuration:
          {
            "mcpServers": {
              "caskmcp": {
                "command": "caskmcp",
                "args": ["mcp", "inspect", "--tools", "/path/to/tools.json"]
              }
            }
          }
        """
        from caskmcp.utils.deps import require_mcp_dependency

        require_mcp_dependency()

        from caskmcp.mcp.meta_server import run_meta_server

        run_meta_server(
            artifacts_dir=artifacts,
            tools_path=tools,
            policy_path=policy,
            lockfile_path=lockfile,
        )

    @mcp.command("meta")
    @click.option(
        "--artifacts", "-a",
        type=click.Path(exists=True),
        help="Path to artifacts directory",
    )
    @click.option(
        "--tools", "-t",
        type=click.Path(exists=True),
        help="Path to tools.json (overrides --artifacts)",
    )
    @click.option(
        "--policy", "-p",
        type=click.Path(exists=True),
        help="Path to policy.yaml (overrides --artifacts)",
    )
    @click.option(
        "--lockfile", "-l",
        type=click.Path(),
        help="Path to lockfile (default: ./caskmcp.lock.yaml)",
    )
    @click.pass_context
    def mcp_meta_alias(
        ctx: click.Context,
        artifacts: str | None,
        tools: str | None,
        policy: str | None,
        lockfile: str | None,
    ) -> None:
        """Alias for `caskmcp mcp inspect`."""
        ctx.invoke(
            mcp_meta,
            artifacts=artifacts,
            tools=tools,
            policy=policy,
            lockfile=lockfile,
        )
