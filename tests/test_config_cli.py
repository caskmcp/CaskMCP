"""Tests for caskmcp config command."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from caskmcp.cli.main import cli
from tests.helpers import write_demo_toolpack


def test_config_outputs_snippet_to_stdout(tmp_path: Path) -> None:
    toolpack_file = write_demo_toolpack(tmp_path)
    runner = CliRunner()

    result = runner.invoke(
        cli,
        ["config", "--toolpack", str(toolpack_file), "--format", "json"],
    )

    assert result.exit_code == 0
    assert result.stderr == ""
    payload = json.loads(result.stdout)
    server = payload["mcpServers"]["tp_demo"]
    assert str(server["command"]).endswith(("cask", "caskmcp"))
    assert server["args"][0] == "--root"
    assert "--toolpack" in server["args"]


def test_config_outputs_codex_toml(tmp_path: Path) -> None:
    toolpack_file = write_demo_toolpack(tmp_path)
    runner = CliRunner()

    result = runner.invoke(
        cli,
        ["config", "--toolpack", str(toolpack_file), "--format", "codex"],
    )

    assert result.exit_code == 0
    assert result.stderr == ""
    stdout = result.stdout
    assert "[mcp_servers.tp_demo]" in stdout
    assert "enabled = true" in stdout
    assert "--toolpack" in stdout
    assert str(toolpack_file.resolve()) in stdout
    assert str((toolpack_file.parent / ".caskmcp").resolve()) in stdout


def test_config_outputs_codex_toml_with_name_override(tmp_path: Path) -> None:
    toolpack_file = write_demo_toolpack(tmp_path)
    runner = CliRunner()

    result = runner.invoke(
        cli,
        [
            "config",
            "--toolpack",
            str(toolpack_file),
            "--format",
            "codex",
            "--name",
            "dummyjson",
        ],
    )

    assert result.exit_code == 0
    assert result.stderr == ""
    assert "[mcp_servers.dummyjson]" in result.stdout
