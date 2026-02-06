"""Tests for mcpmint doctor command."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from mcpmint.cli.main import cli
from tests.helpers import write_demo_toolpack


def test_doctor_outputs_to_stderr_only(tmp_path: Path) -> None:
    toolpack_file = write_demo_toolpack(tmp_path)
    runner = CliRunner()

    result = runner.invoke(
        cli,
        ["doctor", "--toolpack", str(toolpack_file), "--runtime", "local"],
    )

    assert result.exit_code == 0
    assert result.stdout == ""


def test_doctor_container_requires_docker(tmp_path: Path, monkeypatch) -> None:
    toolpack_file = write_demo_toolpack(tmp_path)
    runner = CliRunner()

    monkeypatch.setattr("mcpmint.cli.doctor.docker_available", lambda: False)
    result = runner.invoke(
        cli,
        ["doctor", "--toolpack", str(toolpack_file), "--runtime", "container"],
    )

    assert result.exit_code != 0
