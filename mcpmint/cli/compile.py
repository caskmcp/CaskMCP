"""Compile command implementation."""

from __future__ import annotations

import hashlib
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import click

from mcpmint.core.compile import (
    BaselineGenerator,
    ContractCompiler,
    PolicyGenerator,
    ToolManifestGenerator,
    ToolsetGenerator,
)
from mcpmint.core.normalize import EndpointAggregator
from mcpmint.core.scope import ScopeEngine
from mcpmint.models.capture import CaptureSession
from mcpmint.models.scope import Scope
from mcpmint.storage import Storage
from mcpmint.utils.schema_version import resolve_generated_at


@dataclass(frozen=True)
class CompileResult:
    """Compiled artifact metadata and generated paths."""

    artifact_id: str
    output_path: Path
    scope: Scope
    endpoint_count: int
    generated_at: datetime
    artifacts_created: tuple[tuple[str, Path], ...]
    contract_yaml_path: Path | None = None
    contract_json_path: Path | None = None
    tools_path: Path | None = None
    toolsets_path: Path | None = None
    policy_path: Path | None = None
    baseline_path: Path | None = None


def compile_capture_session(
    session: CaptureSession,
    scope_name: str,
    scope_file: str | None,
    output_format: str,
    output_dir: str | Path,
    deterministic: bool = True,
    verbose: bool = False,
) -> CompileResult:
    """Compile a capture session into MCPMint artifacts."""
    if verbose:
        click.echo(f"Loaded capture: {session.id}")
        click.echo(f"  Exchanges: {len(session.exchanges)}")

    if verbose:
        click.echo("Aggregating endpoints...")

    aggregator = EndpointAggregator(first_party_hosts=session.allowed_hosts)
    endpoints = aggregator.aggregate(session)

    if verbose:
        click.echo(f"  Endpoints: {len(endpoints)}")

    scope_engine = ScopeEngine(first_party_hosts=session.allowed_hosts)
    scope = scope_engine.load_scope(scope_name, scope_file)

    filtered_endpoints = scope_engine.filter_endpoints(endpoints, scope)
    filtered_endpoints = sorted(
        filtered_endpoints,
        key=lambda ep: (ep.host, ep.method.upper(), ep.path, ep.signature_id),
    )

    if verbose:
        click.echo(f"  After scope filter: {len(filtered_endpoints)}")

    generated_at = resolve_generated_at(
        deterministic=deterministic,
        candidate=session.created_at if deterministic else None,
    )
    artifact_id = _generate_artifact_id(
        session_id=session.id,
        scope_name=scope.name,
        output_format=output_format,
        deterministic=deterministic,
    )

    output_path = Path(output_dir) / artifact_id
    output_path.mkdir(parents=True, exist_ok=True)

    artifacts_created: list[tuple[str, Path]] = []
    contract_yaml_path: Path | None = None
    contract_json_path: Path | None = None
    tools_path: Path | None = None
    toolsets_path: Path | None = None
    policy_path: Path | None = None
    baseline_path: Path | None = None

    if output_format in ("all", "openapi", "manifest"):
        compiler = ContractCompiler(
            title=session.name or "Generated API",
            description=f"Generated from capture {session.id}",
        )
        contract = compiler.compile(
            filtered_endpoints,
            scope=scope,
            capture_id=session.id,
            generated_at=generated_at,
        )

        contract_yaml_path = output_path / "contract.yaml"
        with open(contract_yaml_path, "w") as f:
            f.write(compiler.to_yaml(contract))
        artifacts_created.append(("Contract (YAML)", contract_yaml_path))

        contract_json_path = output_path / "contract.json"
        with open(contract_json_path, "w") as f:
            f.write(compiler.to_json(contract))
        artifacts_created.append(("Contract (JSON)", contract_json_path))

    if output_format in ("all", "manifest", "mcp-python"):
        tool_gen = ToolManifestGenerator(
            name=session.name or "Generated Tools",
            description=f"Generated from capture {session.id}",
        )
        manifest = tool_gen.generate(
            filtered_endpoints,
            scope=scope,
            capture_id=session.id,
            generated_at=generated_at,
        )

        tools_path = output_path / "tools.json"
        with open(tools_path, "w") as f:
            f.write(tool_gen.to_json(manifest))
        artifacts_created.append(("Tool Manifest", tools_path))

        toolset_gen = ToolsetGenerator()
        toolsets = toolset_gen.generate(manifest=manifest, generated_at=generated_at)

        toolsets_path = output_path / "toolsets.yaml"
        with open(toolsets_path, "w") as f:
            f.write(toolset_gen.to_yaml(toolsets))
        artifacts_created.append(("Toolsets", toolsets_path))

    if output_format in ("all", "manifest"):
        policy_gen = PolicyGenerator(name=f"{session.name or 'Generated'} Policy")
        policy = policy_gen.generate(filtered_endpoints, scope=scope)

        policy_path = output_path / "policy.yaml"
        with open(policy_path, "w") as f:
            f.write(policy_gen.to_yaml(policy))
        artifacts_created.append(("Policy", policy_path))

        baseline_gen = BaselineGenerator()
        baseline = baseline_gen.generate(
            filtered_endpoints,
            scope=scope,
            capture_id=session.id,
            generated_at=generated_at,
        )

        baseline_path = output_path / "baseline.json"
        with open(baseline_path, "w") as f:
            f.write(baseline_gen.to_json(baseline))
        artifacts_created.append(("Baseline", baseline_path))

    return CompileResult(
        artifact_id=artifact_id,
        output_path=output_path,
        scope=scope,
        endpoint_count=len(filtered_endpoints),
        generated_at=generated_at,
        artifacts_created=tuple(artifacts_created),
        contract_yaml_path=contract_yaml_path,
        contract_json_path=contract_json_path,
        tools_path=tools_path,
        toolsets_path=toolsets_path,
        policy_path=policy_path,
        baseline_path=baseline_path,
    )


def _generate_artifact_id(
    session_id: str,
    scope_name: str,
    output_format: str,
    deterministic: bool,
) -> str:
    """Generate a deterministic or volatile artifact id."""
    if deterministic:
        canonical = f"{session_id}:{scope_name}:{output_format}"
        return f"art_{hashlib.sha256(canonical.encode()).hexdigest()[:12]}"

    import uuid

    return f"art_{datetime.now(UTC).strftime('%Y%m%d')}_{uuid.uuid4().hex[:8]}"


def run_compile(
    capture_id: str,
    scope_name: str,
    scope_file: str | None,
    output_format: str,
    output_dir: str,
    verbose: bool,
    deterministic: bool = True,
) -> None:
    """Run the compile command."""
    storage = Storage()
    session = storage.load_capture(capture_id)

    if not session:
        click.echo(f"Error: Capture not found: {capture_id}", err=True)
        sys.exit(1)

    try:
        result = compile_capture_session(
            session=session,
            scope_name=scope_name,
            scope_file=scope_file,
            output_format=output_format,
            output_dir=output_dir,
            deterministic=deterministic,
            verbose=verbose,
        )
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    if not result.endpoint_count:
        click.echo("Warning: No endpoints match the scope", err=True)

    if output_format == "mcp-python":
        # Generate MCP server (placeholder for now)
        click.echo("Note: MCP server generation coming soon", err=True)

    click.echo(f"\nCompile complete: {result.artifact_id}")
    click.echo(f"  Scope: {result.scope.name}")
    click.echo(f"  Endpoints: {result.endpoint_count}")
    click.echo(f"  Output: {result.output_path}")
    click.echo("\nArtifacts:")
    for name, path in result.artifacts_created:
        click.echo(f"  - {name}: {path.name}")
