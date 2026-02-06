"""Tests for mcpmint config command."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from mcpmint.cli.main import cli
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
    assert server["command"] == "mcpmint"
    assert server["args"][0] == "run"
    assert "--toolpack" in server["args"]
