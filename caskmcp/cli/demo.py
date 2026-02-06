"""Demo command implementation (fixture capture -> compile -> toolpack)."""

from __future__ import annotations

import hashlib
import shutil
import sys
import tempfile
from importlib import resources
from pathlib import Path

import click

from caskmcp.cli.approve import sync_lockfile
from caskmcp.cli.compile import compile_capture_session
from caskmcp.core.capture.har_parser import HARParser
from caskmcp.core.capture.redactor import Redactor
from caskmcp.core.toolpack import (
    Toolpack,
    ToolpackOrigin,
    ToolpackPaths,
    ToolpackRuntime,
    write_toolpack,
)
from caskmcp.storage import Storage


def run_demo(*, output_root: str | None, verbose: bool) -> None:
    """Generate a deterministic offline demo toolpack from bundled fixture data."""
    root = _resolve_output_root(output_root)

    fixture = resources.files("caskmcp.assets.demo").joinpath("sample.har")
    parser = HARParser(allowed_hosts=["api.example.com"])
    with resources.as_file(fixture) as fixture_path:
        session = parser.parse_file(fixture_path, name="CaskMCP Demo")
    if not session.exchanges:
        click.echo("Error: Demo fixture produced no exchanges", err=True)
        sys.exit(1)

    session = Redactor().redact_session(session)

    storage = Storage(base_path=root)
    capture_path = storage.save_capture(session)

    try:
        compile_result = compile_capture_session(
            session=session,
            scope_name="agent_safe_readonly",
            scope_file=None,
            output_format="all",
            output_dir=root / "artifacts",
            deterministic=True,
            verbose=verbose,
        )
    except ValueError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    if not compile_result.tools_path or not compile_result.toolsets_path:
        click.echo("Error: compile did not produce required tools/toolsets artifacts", err=True)
        sys.exit(1)
    if not compile_result.policy_path or not compile_result.baseline_path:
        click.echo("Error: compile did not produce required policy/baseline artifacts", err=True)
        sys.exit(1)

    toolpack_id = _generate_toolpack_id(session.id, compile_result.artifact_id)
    toolpack_dir = root / "toolpacks" / toolpack_id
    artifact_dir = toolpack_dir / "artifact"
    lockfile_dir = toolpack_dir / "lockfile"
    lockfile_dir.mkdir(parents=True, exist_ok=True)

    shutil.copytree(compile_result.output_path, artifact_dir, dirs_exist_ok=True)

    copied_tools = artifact_dir / "tools.json"
    copied_toolsets = artifact_dir / "toolsets.yaml"
    copied_policy = artifact_dir / "policy.yaml"
    copied_baseline = artifact_dir / "baseline.json"

    pending_lockfile = lockfile_dir / "caskmcp.lock.pending.yaml"
    sync_result = sync_lockfile(
        tools_path=str(copied_tools),
        policy_path=str(copied_policy),
        toolsets_path=str(copied_toolsets),
        lockfile_path=str(pending_lockfile),
        capture_id=session.id,
        scope="agent_safe_readonly",
        deterministic=True,
    )

    toolpack = Toolpack(
        toolpack_id=toolpack_id,
        created_at=session.created_at,
        capture_id=session.id,
        artifact_id=compile_result.artifact_id,
        scope="agent_safe_readonly",
        allowed_hosts=sorted(set(session.allowed_hosts)),
        origin=ToolpackOrigin(
            start_url="https://demo.caskmcp.local",
            name="CaskMCP Demo",
        ),
        paths=ToolpackPaths(
            tools=str(copied_tools.relative_to(toolpack_dir)),
            toolsets=str(copied_toolsets.relative_to(toolpack_dir)),
            policy=str(copied_policy.relative_to(toolpack_dir)),
            baseline=str(copied_baseline.relative_to(toolpack_dir)),
            contract_yaml="artifact/contract.yaml",
            contract_json="artifact/contract.json",
            lockfiles={"pending": str(pending_lockfile.relative_to(toolpack_dir))},
        ),
        runtime=ToolpackRuntime(mode="local", container=None),
    )

    toolpack_file = toolpack_dir / "toolpack.yaml"
    write_toolpack(toolpack, toolpack_file)

    click.echo(f"Demo complete: {toolpack_id}")
    click.echo(f"Output root: {root}")
    click.echo(f"Capture: {session.id}")
    click.echo(f"Capture location: {capture_path}")
    click.echo(f"Toolpack: {toolpack_file}")
    click.echo(f"Pending approvals: {sync_result.pending_count}")
    click.echo("Next commands:")
    click.echo(f"  caskmcp run --toolpack {toolpack_file}")
    click.echo(
        "  caskmcp approve tool --all --toolset readonly "
        f"--lockfile {pending_lockfile}"
    )
    click.echo(
        f"  caskmcp drift --baseline {copied_baseline} --capture {session.id}"
    )


def _resolve_output_root(output_root: str | None) -> Path:
    if output_root:
        path = Path(output_root)
        path.mkdir(parents=True, exist_ok=True)
        return path

    return Path(tempfile.mkdtemp(prefix="caskmcp-demo-"))


def _generate_toolpack_id(capture_id: str, artifact_id: str) -> str:
    canonical = f"demo:{capture_id}:{artifact_id}"
    digest = hashlib.sha256(canonical.encode()).hexdigest()[:12]
    return f"tp_{digest}"
