"""Mint command implementation (capture -> compile -> toolpack)."""

from __future__ import annotations

import asyncio
import hashlib
import json
import shutil
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

import click

from mcpmint.cli.approve import sync_lockfile
from mcpmint.cli.compile import compile_capture_session
from mcpmint.core.capture.redactor import Redactor
from mcpmint.core.toolpack import (
    Toolpack,
    ToolpackOrigin,
    ToolpackPaths,
    write_toolpack,
)
from mcpmint.storage import Storage
from mcpmint.utils.schema_version import resolve_generated_at


def run_mint(
    *,
    start_url: str,
    allowed_hosts: list[str],
    name: str | None,
    scope_name: str,
    headless: bool,
    script_path: str | None,
    duration_seconds: int,
    output_root: str,
    deterministic: bool,
    print_mcp_config: bool,
    verbose: bool,
) -> None:
    """Mint a first-class toolpack from browser traffic capture."""
    if script_path and not Path(script_path).exists():
        click.echo(f"Error: Script not found: {script_path}", err=True)
        sys.exit(1)

    if duration_seconds <= 0:
        click.echo("Error: --duration must be > 0", err=True)
        sys.exit(1)

    try:
        from mcpmint.core.capture.playwright_capture import PlaywrightCapture
    except ImportError:
        click.echo("Error: Playwright is required for mint.", err=True)
        click.echo("Install with: pip install 'mcpmint[playwright]'", err=True)
        sys.exit(1)

    if verbose:
        click.echo("Mint step 1/4: capturing traffic...")
        click.echo(f"  Start URL: {start_url}")
        click.echo(f"  Allowed hosts: {', '.join(allowed_hosts)}")
        click.echo(f"  Headless: {headless}")
        if script_path:
            click.echo(f"  Script: {script_path}")
        else:
            click.echo(f"  Duration: {duration_seconds}s")

    capture = PlaywrightCapture(allowed_hosts=allowed_hosts, headless=headless)
    try:
        session = asyncio.run(
            capture.capture(
                start_url=start_url,
                name=name,
                duration_seconds=duration_seconds if not script_path else None,
                script_path=script_path,
                settle_delay_seconds=1.0 if script_path else 0.0,
            )
        )
    except KeyboardInterrupt:
        click.echo("\nMint interrupted.")
        sys.exit(0)
    except Exception as e:
        click.echo(f"Error during capture: {e}", err=True)
        sys.exit(1)

    redactor = Redactor()
    session = redactor.redact_session(session)

    output_base = Path(output_root)
    storage = Storage(base_path=output_base)
    capture_path = storage.save_capture(session)

    if verbose:
        click.echo("Mint step 2/4: compiling artifacts...")

    try:
        compile_result = compile_capture_session(
            session=session,
            scope_name=scope_name,
            scope_file=None,
            output_format="all",
            output_dir=output_base / "artifacts",
            deterministic=deterministic,
            verbose=verbose,
        )
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    if not compile_result.tools_path or not compile_result.toolsets_path:
        click.echo("Error: compile did not produce required tools/toolsets artifacts", err=True)
        sys.exit(1)
    if not compile_result.policy_path or not compile_result.baseline_path:
        click.echo("Error: compile did not produce required policy/baseline artifacts", err=True)
        sys.exit(1)

    if verbose:
        click.echo("Mint step 3/4: creating toolpack...")

    toolpack_id = _generate_toolpack_id(
        capture_id=session.id,
        artifact_id=compile_result.artifact_id,
        scope_name=scope_name,
        start_url=start_url,
        allowed_hosts=allowed_hosts,
        deterministic=deterministic,
    )
    toolpack_dir = output_base / "toolpacks" / toolpack_id
    artifact_dir = toolpack_dir / "artifact"
    lockfile_dir = toolpack_dir / "lockfile"
    toolpack_dir.mkdir(parents=True, exist_ok=True)
    lockfile_dir.mkdir(parents=True, exist_ok=True)
    shutil.copytree(compile_result.output_path, artifact_dir, dirs_exist_ok=True)

    copied_tools = artifact_dir / "tools.json"
    copied_toolsets = artifact_dir / "toolsets.yaml"
    copied_policy = artifact_dir / "policy.yaml"
    copied_baseline = artifact_dir / "baseline.json"
    copied_contract_yaml = artifact_dir / "contract.yaml"
    copied_contract_json = artifact_dir / "contract.json"

    pending_lockfile = lockfile_dir / "mcpmint.lock.pending.yaml"
    sync_result = sync_lockfile(
        tools_path=str(copied_tools),
        policy_path=str(copied_policy),
        toolsets_path=str(copied_toolsets),
        lockfile_path=str(pending_lockfile),
        capture_id=session.id,
        scope=scope_name,
        deterministic=deterministic,
    )

    approved_lockfile = lockfile_dir / "mcpmint.lock.yaml"
    lockfiles: dict[str, str] = {
        "pending": str(pending_lockfile.relative_to(toolpack_dir)),
    }
    if approved_lockfile.exists():
        lockfiles["approved"] = str(approved_lockfile.relative_to(toolpack_dir))

    toolpack = Toolpack(
        toolpack_id=toolpack_id,
        created_at=resolve_generated_at(
            deterministic=deterministic,
            candidate=session.created_at if deterministic else None,
        ),
        capture_id=session.id,
        artifact_id=compile_result.artifact_id,
        scope=scope_name,
        allowed_hosts=sorted(set(allowed_hosts)),
        origin=ToolpackOrigin(start_url=start_url, name=name),
        paths=ToolpackPaths(
            tools=str(copied_tools.relative_to(toolpack_dir)),
            toolsets=str(copied_toolsets.relative_to(toolpack_dir)),
            policy=str(copied_policy.relative_to(toolpack_dir)),
            baseline=str(copied_baseline.relative_to(toolpack_dir)),
            contract_yaml=(
                str(copied_contract_yaml.relative_to(toolpack_dir))
                if copied_contract_yaml.exists()
                else None
            ),
            contract_json=(
                str(copied_contract_json.relative_to(toolpack_dir))
                if copied_contract_json.exists()
                else None
            ),
            lockfiles=lockfiles,
        ),
    )

    toolpack_file = toolpack_dir / "toolpack.yaml"
    write_toolpack(toolpack, toolpack_file)

    click.echo(f"\nMint complete: {toolpack_id}")
    click.echo(f"  Capture: {session.id}")
    click.echo(f"  Capture location: {capture_path}")
    click.echo(f"  Artifact: {compile_result.artifact_id}")
    click.echo(f"  Toolpack: {toolpack_file}")
    click.echo(f"  Pending approvals: {sync_result.pending_count}")

    click.echo("\nNext commands:")
    click.echo(f"  mcpmint mcp serve --toolpack {toolpack_file}")
    click.echo(
        "  mcpmint approve tool --all --toolset readonly "
        f"--lockfile {pending_lockfile}"
    )
    click.echo(
        f"  mcpmint drift --baseline {copied_baseline} --capture {session.id}"
    )

    if print_mcp_config:
        click.echo("\nClaude Desktop MCP config:")
        click.echo(
            build_mcp_config_snippet(
                toolpack_path=toolpack_file,
                server_name=_server_name(name, toolpack_id),
            )
        )


def build_mcp_config_snippet(*, toolpack_path: Path, server_name: str) -> str:
    """Return a ready-to-paste Claude Desktop MCP config snippet."""
    config = {
        "mcpServers": {
            server_name: {
                "command": "mcpmint",
                "args": [
                    "mcp",
                    "serve",
                    "--toolpack",
                    str(toolpack_path.resolve()),
                ],
            }
        }
    }
    return json.dumps(config, indent=2)


def _generate_toolpack_id(
    *,
    capture_id: str,
    artifact_id: str,
    scope_name: str,
    start_url: str,
    allowed_hosts: list[str],
    deterministic: bool,
) -> str:
    """Generate a deterministic or volatile toolpack id."""
    if deterministic:
        canonical = ":".join(
            [
                capture_id,
                artifact_id,
                scope_name,
                start_url,
                ",".join(sorted(set(allowed_hosts))),
            ]
        )
        digest = hashlib.sha256(canonical.encode()).hexdigest()[:12]
        return f"tp_{digest}"

    return f"tp_{datetime.now(UTC).strftime('%Y%m%d')}_{uuid.uuid4().hex[:8]}"


def _server_name(name: str | None, toolpack_id: str) -> str:
    """Create a stable MCP server name from user input."""
    base = (name or toolpack_id).strip().lower().replace(" ", "_")
    sanitized = "".join(ch for ch in base if ch.isalnum() or ch in {"_", "-"})
    return sanitized or toolpack_id
