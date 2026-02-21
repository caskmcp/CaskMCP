"""Init command — auto-detect project context and generate starter config."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
import yaml

from caskmcp.core.init.detector import (
    detect_project,
    generate_config,
    generate_gitignore_entries,
)


def run_init(
    *,
    directory: str,
    verbose: bool,
) -> None:
    """Initialize CaskMCP in a project directory."""
    project_dir = Path(directory).resolve()
    if not project_dir.exists():
        click.echo(f"Error: Directory not found: {project_dir}", err=True)
        sys.exit(1)

    detection = detect_project(project_dir)

    if verbose:
        click.echo("Project detection:")
        click.echo(f"  Type: {detection.project_type}")
        click.echo(f"  Language: {detection.language}")
        click.echo(f"  Package manager: {detection.package_manager}")
        if detection.frameworks:
            click.echo(f"  Frameworks: {', '.join(detection.frameworks)}")
        if detection.api_specs:
            click.echo(f"  API specs: {', '.join(detection.api_specs)}")

    if detection.has_existing_caskmcp:
        click.echo(".caskmcp/ already exists — will not overwrite existing config.")
        if verbose:
            for suggestion in detection.suggestions:
                click.echo(f"  Suggestion: {suggestion}")
        return

    # Create .caskmcp/ directory structure
    caskmcp_dir = project_dir / ".caskmcp"
    caskmcp_dir.mkdir(parents=True, exist_ok=True)
    (caskmcp_dir / "captures").mkdir(exist_ok=True)
    (caskmcp_dir / "artifacts").mkdir(exist_ok=True)
    (caskmcp_dir / "reports").mkdir(exist_ok=True)

    # Write config.yaml
    config = generate_config(detection)
    config_path = caskmcp_dir / "config.yaml"
    config_path.write_text(yaml.dump(config, sort_keys=False), encoding="utf-8")

    # Append to .gitignore if it exists
    gitignore_path = project_dir / ".gitignore"
    gitignore_entries = generate_gitignore_entries()
    if gitignore_path.exists():
        existing = gitignore_path.read_text(encoding="utf-8")
        if "# CaskMCP" not in existing:
            with open(gitignore_path, "a", encoding="utf-8") as f:
                f.write("\n" + "\n".join(gitignore_entries) + "\n")
    else:
        gitignore_path.write_text("\n".join(gitignore_entries) + "\n", encoding="utf-8")

    click.echo(f"✓ Initialized CaskMCP in {caskmcp_dir}")
    click.echo(f"  Config: {config_path}")

    # Print next steps
    click.echo()
    click.echo("What's next:")
    if detection.api_specs:
        spec = detection.api_specs[0]
        click.echo(f"  1. cask capture import {spec} -a <api-host>")
        click.echo("     Then: cask compile -c <capture-id>")
    else:
        click.echo("  1. cask mint <start-url> -a <api-host>")
    click.echo("     mint will print the exact gate and serve commands with correct paths.")
    click.echo("  2. Follow the gate allow + serve commands printed by mint.")
    click.echo("  3. cask config --toolpack <path>   (generate MCP client config)")


def run_mcp_config(
    *,
    toolpack_path: str,
    client: str,
) -> None:
    """Generate MCP client configuration for a toolpack."""
    tp_path = Path(toolpack_path)
    if not tp_path.exists():
        click.echo(f"Error: Toolpack not found: {tp_path}", err=True)
        sys.exit(1)

    config = _build_mcp_client_config(tp_path, client)
    click.echo(json.dumps(config, indent=2))


def _build_mcp_client_config(toolpack_path: Path, client: str) -> dict[str, object]:
    """Build MCP client config for different clients."""
    tp_dir = toolpack_path.parent if toolpack_path.is_file() else toolpack_path
    tp_file = str(toolpack_path.resolve())

    # Try to find tools and policy paths
    tools_path = _find_artifact(tp_dir, "tools.json")
    policy_path = _find_artifact(tp_dir, "policy.yaml")

    base_args = [
        "cask", "run",
        "--toolpack", tp_file,
    ]
    if tools_path:
        base_args.extend(["--tools", str(tools_path)])
    if policy_path:
        base_args.extend(["--policy", str(policy_path)])

    if client in {"claude", "cursor"}:
        return {
            "mcpServers": {
                "cask": {
                    "command": base_args[0],
                    "args": base_args[1:],
                }
            }
        }
    else:
        # Generic stdio config
        return {
            "server": {
                "name": "cask",
                "transport": "stdio",
                "command": base_args,
            }
        }


def _find_artifact(tp_dir: Path, filename: str) -> Path | None:
    """Find an artifact file within the toolpack directory."""
    # Check direct and under artifact/
    for candidate in [tp_dir / filename, tp_dir / "artifact" / filename]:
        if candidate.exists():
            return candidate.resolve()
    return None
