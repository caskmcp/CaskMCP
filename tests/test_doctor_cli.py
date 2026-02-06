"""Tests for mcpmint doctor command."""

from __future__ import annotations

from pathlib import Path

import yaml
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


def test_doctor_reports_missing_artifacts(tmp_path: Path) -> None:
    toolpack_file = write_demo_toolpack(tmp_path)
    tools_path = toolpack_file.parent / "artifact" / "tools.json"
    tools_path.unlink()

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["doctor", "--toolpack", str(toolpack_file), "--runtime", "local"],
    )

    assert result.exit_code != 0
    assert "tools.json missing" in result.stderr


def test_doctor_container_requires_docker(tmp_path: Path, monkeypatch) -> None:
    toolpack_file = write_demo_toolpack(tmp_path)
    runner = CliRunner()

    monkeypatch.setattr("mcpmint.cli.doctor.docker_available", lambda: False)
    result = runner.invoke(
        cli,
        ["doctor", "--toolpack", str(toolpack_file), "--runtime", "container"],
    )

    assert result.exit_code != 0


def test_doctor_auto_container_requires_docker(tmp_path: Path, monkeypatch) -> None:
    toolpack_file = write_demo_toolpack(tmp_path)
    toolpack_dir = toolpack_file.parent
    toolpack_path = toolpack_file

    payload = yaml.safe_load(toolpack_path.read_text()) or {}
    payload["runtime"] = {
        "mode": "container",
        "container": {"image": "mcpmint-toolpack:tp_demo"},
    }
    toolpack_path.write_text(yaml.safe_dump(payload, sort_keys=False))

    for name in ("Dockerfile", "entrypoint.sh", "mcpmint.run", "requirements.lock"):
        (toolpack_dir / name).write_text("stub\n")

    runner = CliRunner()
    monkeypatch.setattr("mcpmint.cli.doctor.docker_available", lambda: False)
    result = runner.invoke(
        cli,
        ["doctor", "--toolpack", str(toolpack_file), "--runtime", "auto"],
    )

    assert result.exit_code != 0
    assert "docker not available" in result.stderr


def test_doctor_handles_mcp_spec_error(tmp_path: Path, monkeypatch) -> None:
    toolpack_file = write_demo_toolpack(tmp_path)
    runner = CliRunner()

    def _raise_value_error(_name: str) -> None:
        raise ValueError("mcp.__spec__ is None")

    monkeypatch.setattr("importlib.util.find_spec", _raise_value_error)
    result = runner.invoke(
        cli,
        ["doctor", "--toolpack", str(toolpack_file), "--runtime", "local"],
    )

    assert result.exit_code != 0
    assert 'mcp not installed' in result.stderr
