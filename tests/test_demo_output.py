"""Tests for demo command output format and content."""

from __future__ import annotations

from click.testing import CliRunner

from caskmcp.cli.main import cli


def test_demo_output_contains_tool_table() -> None:
    """Demo output includes tool count and method/path table."""
    runner = CliRunner()
    result = runner.invoke(cli, ["demo"])

    assert result.exit_code == 0
    assert "tools compiled" in result.stdout


def test_demo_output_contains_correct_next_step_commands() -> None:
    """Demo output prints exact flag forms for gate, run, and drift."""
    runner = CliRunner()
    result = runner.invoke(cli, ["demo"])

    assert result.exit_code == 0
    assert "cask gate allow --all --lockfile" in result.stdout
    assert "cask run --toolpack" in result.stdout
    assert "cask drift --baseline" in result.stdout


def test_demo_output_tool_count_is_8() -> None:
    """Demo fixture produces exactly 8 tools (frozen bundled fixture)."""
    runner = CliRunner()
    result = runner.invoke(cli, ["demo"])

    assert result.exit_code == 0
    assert "8 tools compiled" in result.stdout


def test_demo_output_contains_artifact_paths() -> None:
    """Demo output prints Toolpack, Pending lock, and Baseline lines."""
    runner = CliRunner()
    result = runner.invoke(cli, ["demo"])

    assert result.exit_code == 0
    assert "Toolpack:" in result.stdout
    assert "Pending lock:" in result.stdout
    assert "Baseline:" in result.stdout
