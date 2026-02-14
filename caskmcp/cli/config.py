"""Config snippet command implementation."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from caskmcp.core.toolpack import load_toolpack
from caskmcp.utils.config import build_mcp_config_payload, render_config_payload


def run_config(toolpack_path: str, fmt: str, *, name_override: str | None = None) -> None:
    """Emit an MCP client config snippet."""
    try:
        toolpack = load_toolpack(Path(toolpack_path))
    except (FileNotFoundError, ValueError) as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    payload = build_mcp_config_payload(
        toolpack_path=Path(toolpack_path),
        server_name=name_override or toolpack.toolpack_id,
    )
    click.echo(render_config_payload(payload, fmt))
