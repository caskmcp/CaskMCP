"""MCP client config snippet helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml


def build_mcp_config_payload(*, toolpack_path: Path, server_name: str) -> dict[str, Any]:
    """Build a config payload for MCP clients."""
    return {
        "mcpServers": {
            server_name: {
                "command": "caskmcp",
                "args": [
                    "run",
                    "--toolpack",
                    str(toolpack_path),
                ],
            }
        }
    }


def render_config_payload(payload: dict[str, Any], fmt: str) -> str:
    """Render config payload to json or yaml."""
    if fmt == "yaml":
        return yaml.safe_dump(payload, sort_keys=True)
    return json.dumps(payload, indent=2, sort_keys=True)
