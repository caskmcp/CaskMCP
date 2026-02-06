"""MCP server command implementation."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from caskmcp.utils.deps import require_mcp_dependency


def run_mcp_serve(
    tools_path: str | None,
    toolpack_path: str | None,
    toolsets_path: str | None,
    toolset_name: str | None,
    policy_path: str | None,
    lockfile_path: str | None,
    base_url: str | None,
    auth_header: str | None,
    audit_log: str | None,
    dry_run: bool,
    confirmation_store_path: str,
    allow_private_cidrs: list[str],
    allow_redirects: bool,
    verbose: bool,
) -> None:
    """Run the MCP server command.

    Args:
        tools_path: Path to tools.json manifest
        toolpack_path: Path to toolpack.yaml metadata
        toolsets_path: Path to toolsets.yaml artifact
        toolset_name: Named toolset to expose
        policy_path: Path to policy.yaml file
        lockfile_path: Path to approval lockfile (optional)
        base_url: Base URL for upstream API
        auth_header: Authorization header value
        audit_log: Path for audit log
        dry_run: Evaluate but don't execute
        verbose: Enable verbose output
    """
    resolved_toolpack = None
    resolved_toolpack_paths = None
    if toolpack_path:
        from caskmcp.core.toolpack import load_toolpack, resolve_toolpack_paths

        try:
            resolved_toolpack = load_toolpack(toolpack_path)
            resolved_toolpack_paths = resolve_toolpack_paths(
                toolpack=resolved_toolpack,
                toolpack_path=toolpack_path,
            )
        except (FileNotFoundError, ValueError) as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)

    resolved_tools_path = Path(tools_path) if tools_path else None
    if resolved_tools_path is None and resolved_toolpack_paths is not None:
        resolved_tools_path = resolved_toolpack_paths.tools_path

    if resolved_tools_path is None:
        click.echo("Error: Provide --tools or --toolpack.", err=True)
        sys.exit(1)
    if not resolved_tools_path.exists():
        click.echo(f"Error: Tools manifest not found: {resolved_tools_path}", err=True)
        sys.exit(1)

    resolved_policy_path: Path | None = None
    if policy_path:
        resolved_policy_path = Path(policy_path)
    elif resolved_toolpack_paths is not None:
        resolved_policy_path = resolved_toolpack_paths.policy_path

    # Validate policy file if provided
    if resolved_policy_path and not resolved_policy_path.exists():
        click.echo(f"Error: Policy file not found: {resolved_policy_path}", err=True)
        sys.exit(1)

    resolved_toolsets_path: Path | None = None
    if toolsets_path:
        resolved_toolsets_path = Path(toolsets_path)
    elif resolved_toolpack_paths is not None:
        resolved_toolsets_path = resolved_toolpack_paths.toolsets_path
    else:
        candidate = resolved_tools_path.parent / "toolsets.yaml"
        if candidate.exists():
            resolved_toolsets_path = candidate

    resolved_lockfile_path: Path | None = None
    if lockfile_path:
        resolved_lockfile_path = Path(lockfile_path)
    elif (
        resolved_toolpack_paths is not None
        and resolved_toolpack_paths.approved_lockfile_path is not None
        and resolved_toolpack_paths.approved_lockfile_path.exists()
    ):
        resolved_lockfile_path = resolved_toolpack_paths.approved_lockfile_path

    if resolved_lockfile_path and not resolved_lockfile_path.exists():
        click.echo(f"Error: Lockfile not found: {resolved_lockfile_path}", err=True)
        sys.exit(1)

    if toolset_name and (resolved_toolsets_path is None or not resolved_toolsets_path.exists()):
        click.echo(
            "Error: Toolset selection requires a toolsets artifact. "
            "Pass --toolsets <path> or compile artifacts including toolsets.yaml.",
            err=True,
        )
        sys.exit(1)

    effective_toolset = toolset_name
    if effective_toolset is None and resolved_toolsets_path and resolved_toolsets_path.exists():
        effective_toolset = "readonly"
        if verbose:
            click.echo(
                "Defaulting to toolset readonly. Use --toolset <name> to change.",
                err=True,
            )

    if verbose:
        click.echo("Starting CaskMCP MCP Server...", err=True)
        click.echo(f"  Tools: {resolved_tools_path}", err=True)
        if toolpack_path:
            click.echo(f"  Toolpack: {toolpack_path}", err=True)
        if resolved_toolsets_path:
            click.echo(f"  Toolsets: {resolved_toolsets_path}", err=True)
        if effective_toolset:
            click.echo(f"  Selected toolset: {effective_toolset}", err=True)
        if resolved_policy_path:
            click.echo(f"  Policy: {resolved_policy_path}", err=True)
        if resolved_lockfile_path:
            click.echo(f"  Lockfile: {resolved_lockfile_path}", err=True)
        elif (
            resolved_toolpack is not None
            and resolved_toolpack.paths.lockfiles.get("pending")
        ):
            click.echo(
                "  Lockfile: none selected (toolpack has pending approvals only)",
                err=True,
            )
        if base_url:
            click.echo(f"  Base URL: {base_url}", err=True)
        if audit_log:
            click.echo(f"  Audit log: {audit_log}", err=True)
        if dry_run:
            click.echo("  Mode: DRY RUN (no actual requests)", err=True)

    require_mcp_dependency()

    # Import here to avoid loading MCP dependencies unless needed
    from caskmcp.mcp.server import run_mcp_server

    run_mcp_server(
        tools_path=str(resolved_tools_path),
        toolsets_path=str(resolved_toolsets_path) if resolved_toolsets_path else None,
        toolset_name=effective_toolset,
        policy_path=str(resolved_policy_path) if resolved_policy_path else None,
        lockfile_path=str(resolved_lockfile_path) if resolved_lockfile_path else None,
        base_url=base_url,
        auth_header=auth_header,
        audit_log=audit_log,
        dry_run=dry_run,
        confirmation_store_path=confirmation_store_path,
        allow_private_cidrs=allow_private_cidrs,
        allow_redirects=allow_redirects,
    )
