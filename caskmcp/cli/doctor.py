"""Doctor command implementation."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from caskmcp.core.approval import LockfileManager, compute_artifacts_digest_from_paths
from caskmcp.core.toolpack import load_toolpack, resolve_toolpack_paths
from caskmcp.utils.deps import has_mcp_dependency
from caskmcp.utils.runtime import docker_available


def run_doctor(
    toolpack_path: str,
    runtime: str,
    verbose: bool,
    require_local_mcp: bool = False,
) -> None:
    """Validate toolpack readiness for execution."""
    errors: list[str] = []
    warnings: list[str] = []

    try:
        toolpack = load_toolpack(Path(toolpack_path))
    except (FileNotFoundError, ValueError) as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    resolved = resolve_toolpack_paths(toolpack=toolpack, toolpack_path=toolpack_path)
    toolpack_root = Path(toolpack_path).resolve().parent

    if not resolved.tools_path.exists():
        errors.append(f"tools.json missing: {resolved.tools_path}")
    if not resolved.toolsets_path.exists():
        errors.append(f"toolsets.yaml missing: {resolved.toolsets_path}")
    if not resolved.policy_path.exists():
        errors.append(f"policy.yaml missing: {resolved.policy_path}")
    if not resolved.baseline_path.exists():
        errors.append(f"baseline.json missing: {resolved.baseline_path}")

    lockfile_path = resolved.approved_lockfile_path or resolved.pending_lockfile_path
    if lockfile_path is None or not lockfile_path.exists():
        errors.append("lockfile missing; run caskmcp approve sync")
    else:
        manager = LockfileManager(lockfile_path)
        lockfile = manager.load()
        if not errors:
            digest = compute_artifacts_digest_from_paths(
                tools_path=resolved.tools_path,
                toolsets_path=resolved.toolsets_path,
                policy_path=resolved.policy_path,
            )
            if lockfile.artifacts_digest and lockfile.artifacts_digest != digest:
                errors.append("lockfile artifacts digest mismatch; re-run caskmcp approve sync")

            expected_hash = lockfile.evidence_summary_sha256
            if expected_hash:
                actual_hash = None
                if (
                    resolved.evidence_summary_sha256_path
                    and resolved.evidence_summary_sha256_path.exists()
                ):
                    actual_hash = resolved.evidence_summary_sha256_path.read_text().strip()
                if actual_hash != expected_hash:
                    errors.append("evidence summary hash mismatch; re-run verification")

    mode = runtime
    if mode == "auto":
        mode = toolpack.runtime.mode if toolpack.runtime else "local"

    if mode == "local":
        if require_local_mcp and not has_mcp_dependency():
            errors.append('mcp not installed. Install with: pip install "caskmcp[mcp]"')
    elif mode == "container":
        if toolpack.runtime is None or toolpack.runtime.container is None:
            errors.append("runtime container configuration missing in toolpack")
        else:
            container = toolpack.runtime.container
            dockerfile = toolpack_root / container.dockerfile
            entrypoint = toolpack_root / container.entrypoint
            run_wrapper = toolpack_root / container.run
            requirements = toolpack_root / container.requirements
            for path in (dockerfile, entrypoint, run_wrapper, requirements):
                if not path.exists():
                    errors.append(f"container runtime file missing: {path}")
        if not docker_available():
            errors.append("docker not available; install Docker or use --runtime local")
    else:
        errors.append(f"unknown runtime mode: {mode}")

    if errors:
        for error in errors:
            click.echo(f"Error: {error}", err=True)
        click.echo("Doctor failed.", err=True)
        click.echo("Next: fix the errors above and re-run `caskmcp doctor --toolpack <path>`.", err=True)
        sys.exit(1)

    if warnings:
        for warning in warnings:
            click.echo(f"Warning: {warning}", err=True)

    click.echo("Doctor check passed.", err=True)
    click.echo(f"Next: caskmcp run --toolpack {toolpack_path}", err=True)
    click.echo(
        f"      caskmcp run --toolpack {toolpack_path} --print-config-and-exit",
        err=True,
    )

    if verbose:
        click.echo(f"Runtime mode: {mode}", err=True)
