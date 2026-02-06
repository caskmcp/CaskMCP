"""Tests for the `caskmcp demo` command."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from caskmcp.cli.main import cli


def _extract_output_root(stdout: str) -> Path:
    for line in stdout.splitlines():
        if line.startswith("Output root: "):
            return Path(line.split("Output root: ", 1)[1].strip())
    raise AssertionError("Output root line missing")


def test_demo_default_temp_output_and_clean_stderr() -> None:
    runner = CliRunner()

    result = runner.invoke(cli, ["demo"])

    assert result.exit_code == 0
    assert result.stderr == ""
    assert "Demo complete:" in result.stdout
    assert "Next commands:" in result.stdout

    output_root = _extract_output_root(result.stdout)
    assert output_root.exists()
    assert (output_root / "captures").exists()
    assert (output_root / "artifacts").exists()
    assert (output_root / "toolpacks").exists()


def test_demo_out_override(tmp_path: Path) -> None:
    runner = CliRunner()
    output_root = tmp_path / "demo-output"

    result = runner.invoke(cli, ["demo", "--out", str(output_root)])

    assert result.exit_code == 0
    assert result.stderr == ""
    assert f"Output root: {output_root}" in result.stdout
    assert output_root.exists()
    assert (output_root / "captures").exists()
    assert (output_root / "artifacts").exists()
    assert (output_root / "toolpacks").exists()
