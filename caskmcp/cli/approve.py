"""Approval command implementation."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import click
import yaml

from caskmcp.core.approval import (
    ApprovalStatus,
    LockfileManager,
    compute_artifacts_digest_from_paths,
)
from caskmcp.core.approval.snapshot import materialize_snapshot, resolve_toolpack_root
from caskmcp.utils.schema_version import resolve_schema_version


@dataclass(frozen=True)
class ApprovalSyncResult:
    """Result payload for lockfile sync operations."""

    lockfile_path: Path
    artifacts_digest: str
    changes: dict[str, list[str]]
    has_pending: bool
    pending_count: int


def sync_lockfile(
    *,
    tools_path: str,
    policy_path: str | None,
    toolsets_path: str | None,
    lockfile_path: str | None,
    capture_id: str | None,
    scope: str | None,
    deterministic: bool,
    evidence_summary_sha256: str | None = None,
) -> ApprovalSyncResult:
    """Sync a lockfile from manifest + optional policy/toolsets."""
    if not Path(tools_path).exists():
        raise FileNotFoundError(f"Tools manifest not found: {tools_path}")

    with open(tools_path) as f:
        manifest = json.load(f)
    resolve_schema_version(manifest, artifact="tools manifest", allow_legacy=True)

    toolsets: dict[str, Any] | None = None
    resolved_toolsets: Path | None = None
    if toolsets_path:
        resolved_toolsets = Path(toolsets_path)
    else:
        candidate = Path(tools_path).parent / "toolsets.yaml"
        if candidate.exists():
            resolved_toolsets = candidate

    if resolved_toolsets:
        if not resolved_toolsets.exists():
            raise FileNotFoundError(f"Toolsets artifact not found: {resolved_toolsets}")
        with open(resolved_toolsets) as f:
            toolsets = yaml.safe_load(f) or {}
        resolve_schema_version(toolsets, artifact="toolsets artifact", allow_legacy=False)

    manager = LockfileManager(lockfile_path)
    manager.load()

    resolved_policy: Path | None = None
    if policy_path:
        resolved_policy = Path(policy_path)
    else:
        candidate_policy = Path(tools_path).parent / "policy.yaml"
        if candidate_policy.exists():
            resolved_policy = candidate_policy

    artifacts_digest = compute_artifacts_digest_from_paths(
        tools_path=tools_path,
        toolsets_path=resolved_toolsets,
        policy_path=resolved_policy,
    )

    changes = manager.sync_from_manifest(
        manifest=manifest,
        capture_id=capture_id,
        scope=scope,
        toolsets=toolsets,
        deterministic=deterministic,
    )
    manager.set_artifacts_digest(artifacts_digest)
    if evidence_summary_sha256:
        manager.set_evidence_summary_sha256(evidence_summary_sha256)
    manager.save()

    pending = manager.get_pending()
    return ApprovalSyncResult(
        lockfile_path=manager.lockfile_path,
        artifacts_digest=artifacts_digest,
        changes=changes,
        has_pending=bool(pending),
        pending_count=len(pending),
    )


def run_approve_sync(
    tools_path: str,
    policy_path: str | None,
    toolsets_path: str | None,
    lockfile_path: str | None,
    capture_id: str | None,
    scope: str | None,
    verbose: bool,
    deterministic: bool = True,
) -> None:
    """Sync lockfile with a tools manifest.

    Args:
        tools_path: Path to tools.json manifest
        toolsets_path: Path to toolsets.yaml artifact (optional)
        lockfile_path: Path to lockfile
        capture_id: Optional capture ID
        scope: Optional scope name
        verbose: Enable verbose output
    """
    if not policy_path and not (Path(tools_path).parent / "policy.yaml").exists():
        click.echo(
            "Warning: No policy.yaml provided/found; lockfile digest will not bind policy changes.",
            err=True,
        )

    try:
        result = sync_lockfile(
            tools_path=tools_path,
            policy_path=policy_path,
            toolsets_path=toolsets_path,
            lockfile_path=lockfile_path,
            capture_id=capture_id,
            scope=scope,
            deterministic=deterministic,
        )
    except FileNotFoundError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    # Report
    click.echo(f"Synced lockfile: {result.lockfile_path}")
    click.echo(f"  Artifacts digest: {result.artifacts_digest[:16]}...")
    click.echo(f"  New tools: {len(result.changes['new'])}")
    click.echo(f"  Modified: {len(result.changes['modified'])}")
    click.echo(f"  Removed: {len(result.changes['removed'])}")
    click.echo(f"  Unchanged: {len(result.changes['unchanged'])}")

    if verbose:
        manager = LockfileManager(result.lockfile_path)
        manager.load()

        if result.changes["new"]:
            click.echo("\nNew tools (pending approval):")
            for tool_identifier in result.changes["new"]:
                tool = manager.get_tool(tool_identifier)
                if tool:
                    click.echo(f"  - {tool.name} [{tool.risk_tier}] {tool.method} {tool.path}")

        if result.changes["modified"]:
            click.echo("\nModified tools (re-approval required):")
            for tool_identifier in result.changes["modified"]:
                tool = manager.get_tool(tool_identifier)
                if tool:
                    click.echo(f"  - {tool.name} [{tool.change_type}] {tool.method} {tool.path}")

    # Exit code based on pending status
    if result.has_pending:
        click.echo(f"\n⚠️  {result.pending_count} tools pending approval")
        sys.exit(1)
    else:
        click.echo("\n✓ All tools approved")


def run_approve_list(
    lockfile_path: str | None,
    status_filter: str | None,
    verbose: bool,
) -> None:
    """List tool approvals.

    Args:
        lockfile_path: Path to lockfile
        status_filter: Filter by status (pending, approved, rejected)
        verbose: Enable verbose output
    """
    manager = LockfileManager(lockfile_path)

    if not manager.exists():
        click.echo(f"No lockfile found at: {manager.lockfile_path}")
        click.echo("Run 'caskmcp approve sync' first to create one.")
        sys.exit(1)

    manager.load()
    lockfile = manager.lockfile
    assert lockfile is not None

    # Filter tools
    if status_filter:
        try:
            status = ApprovalStatus(status_filter)
            tools = [t for t in lockfile.tools.values() if t.status == status]
        except ValueError:
            click.echo(f"Invalid status: {status_filter}", err=True)
            click.echo("Valid statuses: pending, approved, rejected")
            sys.exit(1)
    else:
        tools = list(lockfile.tools.values())

    # Display
    click.echo(f"Lockfile: {manager.lockfile_path}")
    click.echo(f"Total: {lockfile.total_tools} | Approved: {lockfile.approved_count} | Pending: {lockfile.pending_count} | Rejected: {lockfile.rejected_count}")
    click.echo()

    if not tools:
        click.echo("No tools found matching filter.")
        return

    for tool in sorted(tools, key=lambda t: t.name):
        status_icon = {
            ApprovalStatus.APPROVED: "✓",
            ApprovalStatus.PENDING: "○",
            ApprovalStatus.REJECTED: "✗",
        }[tool.status]

        risk_color = {
            "low": "green",
            "medium": "yellow",
            "high": "red",
            "critical": "bright_red",
        }.get(tool.risk_tier, "white")

        click.echo(
            f"  {status_icon} {tool.name} "
            f"[{click.style(tool.risk_tier, fg=risk_color)}] "
            f"{tool.method} {tool.path}"
        )

        if verbose:
            click.echo(f"      Host: {tool.host}")
            click.echo(f"      Signature: {tool.signature_id[:16]}...")
            click.echo(f"      Version: {tool.tool_version}")
            if tool.approved_by:
                click.echo(f"      Approved by: {tool.approved_by} at {tool.approved_at}")
            if tool.change_type:
                click.echo(f"      Change: {tool.change_type} at {tool.changed_at}")
            click.echo()


def run_approve_tool(
    tool_ids: tuple[str, ...],
    lockfile_path: str | None,
    all_pending: bool,
    toolset: str | None,
    approved_by: str | None,
    verbose: bool,  # noqa: ARG001
) -> None:
    """Approve one or more tools.

    Args:
        tool_ids: Tool IDs to approve
        lockfile_path: Path to lockfile
        all_pending: Approve all pending tools
        toolset: Optional toolset name for scoped approvals
        approved_by: Who is approving
        verbose: Enable verbose output
    """
    manager = LockfileManager(lockfile_path)

    if not manager.exists():
        click.echo(f"No lockfile found at: {manager.lockfile_path}", err=True)
        sys.exit(1)

    manager.load()

    if all_pending:
        count = manager.approve_all(approved_by, toolset=toolset)
        manager.save()
        click.echo(f"Approved {count} tools")
        _maybe_materialize_snapshot(manager)
        return

    if not tool_ids:
        click.echo("Error: Specify tool IDs to approve or use --all", err=True)
        sys.exit(1)

    approved = []
    not_found = []

    for tool_id in tool_ids:
        if manager.approve(tool_id, approved_by, toolset=toolset):
            approved.append(tool_id)
        else:
            not_found.append(tool_id)

    manager.save()

    if approved:
        click.echo(f"Approved: {', '.join(approved)}")

    if not_found:
        click.echo(f"Not found: {', '.join(not_found)}", err=True)
        sys.exit(1)

    _maybe_materialize_snapshot(manager)


def run_approve_reject(
    tool_ids: tuple[str, ...],
    lockfile_path: str | None,
    reason: str | None,
    verbose: bool,  # noqa: ARG001
) -> None:
    """Reject one or more tools.

    Args:
        tool_ids: Tool IDs to reject
        lockfile_path: Path to lockfile
        reason: Rejection reason
        verbose: Enable verbose output
    """
    manager = LockfileManager(lockfile_path)

    if not manager.exists():
        click.echo(f"No lockfile found at: {manager.lockfile_path}", err=True)
        sys.exit(1)

    manager.load()

    if not tool_ids:
        click.echo("Error: Specify tool IDs to reject", err=True)
        sys.exit(1)

    rejected = []
    not_found = []

    for tool_id in tool_ids:
        if manager.reject(tool_id, reason):
            rejected.append(tool_id)
        else:
            not_found.append(tool_id)

    manager.save()

    if rejected:
        click.echo(f"Rejected: {', '.join(rejected)}")

    if not_found:
        click.echo(f"Not found: {', '.join(not_found)}", err=True)
        sys.exit(1)


def run_approve_snapshot(
    lockfile_path: str | None,
    verbose: bool,
) -> None:
    """Materialize baseline snapshot for an approved lockfile."""
    manager = LockfileManager(lockfile_path)

    if not manager.exists():
        click.echo(f"No lockfile found at: {manager.lockfile_path}")
        click.echo("Run 'caskmcp approve sync' first.")
        sys.exit(2)

    manager.load()
    approvals_passed, message = manager.check_approvals()
    if not approvals_passed:
        click.echo(f"Cannot snapshot: {message}")
        sys.exit(1)

    _materialize_snapshot(manager, verbose=verbose, require_toolpack=True)


def run_approve_check(
    lockfile_path: str | None,
    toolset: str | None,
    verbose: bool,
) -> None:
    """Check if all tools are approved (for CI).

    Args:
        lockfile_path: Path to lockfile
        toolset: Optional toolset name for scoped CI checks
        verbose: Enable verbose output
    """
    manager = LockfileManager(lockfile_path)

    if not manager.exists():
        click.echo(f"No lockfile found at: {manager.lockfile_path}")
        click.echo("Run 'caskmcp approve sync' first.")
        sys.exit(2)

    manager.load()

    passed, message = manager.check_ci(toolset=toolset)

    if passed:
        click.echo(f"✓ {message}")
        sys.exit(0)
    else:
        click.echo(f"✗ {message}")

        if verbose:
            pending = manager.get_pending(toolset=toolset)
            if pending:
                click.echo("\nPending tools:")
                for tool in pending:
                    click.echo(f"  - {tool.name} [{tool.risk_tier}] {tool.method} {tool.path}")

        sys.exit(1)


def _materialize_snapshot(
    manager: LockfileManager,
    *,
    verbose: bool,
    require_toolpack: bool,
) -> None:
    toolpack_root = resolve_toolpack_root(manager.lockfile_path)
    if toolpack_root is None:
        if require_toolpack:
            click.echo("toolpack.yaml not found; cannot materialize snapshot", err=True)
            sys.exit(1)
        return

    result = materialize_snapshot(manager.lockfile_path)
    relative_dir = result.snapshot_dir.relative_to(toolpack_root)
    manager.set_baseline_snapshot(str(relative_dir), result.digest)
    manager.save()

    if verbose:
        status = "created" if result.created else "reused"
        click.echo(f"Baseline snapshot {status}: {relative_dir}")


def _maybe_materialize_snapshot(manager: LockfileManager) -> None:
    approvals_passed, _message = manager.check_approvals()
    if not approvals_passed:
        return
    _materialize_snapshot(manager, verbose=False, require_toolpack=False)
