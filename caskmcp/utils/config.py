"""MCP client config snippet helpers."""

from __future__ import annotations

import json
import re
import shutil
import sys
from pathlib import Path
from typing import Any

import yaml


def _resolve_caskmcp_command() -> str:
    """Return an absolute `caskmcp` command path when possible.

    Claude Desktop often does not inherit a shell PATH (especially virtualenv PATH),
    so emitting an absolute path improves "paste-and-go" reliability.
    """
    argv0 = Path(sys.argv[0])
    if argv0.name in {"caskmcp", "cask"}:
        # Prefer the currently-running entrypoint when it is an absolute, existing path.
        # This avoids accidentally emitting a different caskmcp found on PATH (for example,
        # a repo venv vs a standalone install).
        if argv0.exists():
            return str(argv0.resolve())

        discovered_self = shutil.which(argv0.name)
        if discovered_self:
            return discovered_self

    discovered = shutil.which("caskmcp")
    if discovered:
        return discovered

    return "caskmcp"


def build_mcp_config_payload(*, toolpack_path: Path, server_name: str) -> dict[str, Any]:
    """Build a config payload for MCP clients."""
    toolpack_abs = toolpack_path.resolve()
    toolpack_root = toolpack_abs.parent
    # Use a toolpack-local root so Claude Desktop can start the server regardless of its cwd.
    state_root = (toolpack_root / ".caskmcp").resolve()

    return {
        "mcpServers": {
            server_name: {
                "command": _resolve_caskmcp_command(),
                "args": [
                    "--root",
                    str(state_root),
                    "mcp",
                    "serve",
                    "--toolpack",
                    str(toolpack_abs),
                ],
            }
        }
    }


def render_config_payload(payload: dict[str, Any], fmt: str) -> str:
    """Render config payload to json, yaml, or Codex TOML."""
    if fmt == "codex":
        servers = payload.get("mcpServers")
        if not isinstance(servers, dict) or not servers:
            raise ValueError("Invalid MCP config payload: missing mcpServers")

        def _toml_key_segment(key: str) -> str:
            if re.fullmatch(r"[A-Za-z0-9_-]+", key):
                return key
            # Use JSON string quoting for TOML basic string escape compatibility.
            return json.dumps(key)

        def _toml_quote(value: str) -> str:
            return json.dumps(value)

        stanzas: list[str] = []
        for server_name, server in servers.items():
            if not isinstance(server_name, str) or not isinstance(server, dict):
                continue
            command = server.get("command")
            args = server.get("args")
            if not isinstance(command, str) or not isinstance(args, list) or not all(
                isinstance(item, str) for item in args
            ):
                raise ValueError("Invalid MCP config payload: server missing command/args")

            header = f"[mcp_servers.{_toml_key_segment(server_name)}]"
            rendered_args = ", ".join(_toml_quote(item) for item in args)
            stanzas.append(
                "\n".join(
                    [
                        header,
                        f"args = [{rendered_args}]",
                        f"command = {_toml_quote(command)}",
                        "enabled = true",
                    ]
                )
            )

        return "\n\n".join(stanzas) + "\n"

    if fmt == "yaml":
        return yaml.safe_dump(payload, sort_keys=True)
    return json.dumps(payload, indent=2, sort_keys=True)
