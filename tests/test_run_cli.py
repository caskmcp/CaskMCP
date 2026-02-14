"""Tests for caskmcp run command."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from caskmcp.cli.main import cli
from tests.helpers import write_demo_toolpack


def test_run_print_config_and_exit(tmp_path: Path) -> None:
    toolpack_file = write_demo_toolpack(tmp_path)
    runner = CliRunner()

    result = runner.invoke(
        cli,
        ["run", "--toolpack", str(toolpack_file), "--print-config-and-exit"],
    )

    assert result.exit_code == 0
    assert result.stderr == ""
    payload = json.loads(result.stdout)
    server = payload["mcpServers"]["tp_demo"]
    assert str(server["command"]).endswith("caskmcp")
    assert server["args"][0] == "--root"
    assert "mcp" in server["args"]
    assert "serve" in server["args"]


def test_run_container_requires_docker(tmp_path: Path, monkeypatch) -> None:
    toolpack_file = write_demo_toolpack(tmp_path)
    runner = CliRunner()

    monkeypatch.setattr("caskmcp.cli.run.docker_available", lambda: False)
    result = runner.invoke(
        cli,
        ["run", "--toolpack", str(toolpack_file), "--runtime", "container"],
    )

    assert result.exit_code != 0
    assert result.stdout == ""
