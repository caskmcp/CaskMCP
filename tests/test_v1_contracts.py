"""Focused tests for v1 contract hardening."""

from __future__ import annotations

import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from caskmcp.cli.main import cli
from caskmcp.cli.mcp import run_mcp_serve
from caskmcp.core.approval import LockfileManager
from tests.helpers import write_demo_toolpack


def test_cli_surfaces_diff_gate_and_mcp_inspect() -> None:
    runner = CliRunner()
    top_help = runner.invoke(cli, ["--help"])
    assert top_help.exit_code == 0
    assert "diff" in top_help.stdout
    assert "gate" in top_help.stdout

    mcp_help = runner.invoke(cli, ["mcp", "--help"])
    assert mcp_help.exit_code == 0
    assert "inspect" in mcp_help.stdout


def test_default_help_hides_advanced_commands_but_help_all_shows_them() -> None:
    runner = CliRunner()

    default_help = runner.invoke(cli, ["--help"])
    assert default_help.exit_code == 0
    default_lines = default_help.stdout.splitlines()
    assert any(line.strip().startswith("mint") for line in default_lines)
    assert not any(line.strip().startswith("approve") for line in default_lines)
    assert not any(line.strip().startswith("capture") for line in default_lines)
    assert not any(line.strip().startswith("compile") for line in default_lines)

    help_all = runner.invoke(cli, ["--help-all"])
    assert help_all.exit_code == 0
    assert "approve" in help_all.stdout
    assert "capture" in help_all.stdout
    assert "compile" in help_all.stdout
    assert "doctor" in help_all.stdout
    assert "bundle" in help_all.stdout


def test_diff_and_plan_share_implementation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    toolpack = write_demo_toolpack(tmp_path)
    calls: list[dict[str, object]] = []

    def _capture_run_plan(**kwargs):  # noqa: ANN003
        calls.append(kwargs)

    monkeypatch.setattr("caskmcp.cli.plan.run_plan", _capture_run_plan)
    runner = CliRunner()

    diff_result = runner.invoke(cli, ["diff", "--toolpack", str(toolpack)])
    plan_result = runner.invoke(cli, ["plan", "--toolpack", str(toolpack)])

    assert diff_result.exit_code == 0
    assert plan_result.exit_code == 0
    assert len(calls) == 2
    assert calls[0]["toolpack_path"] == calls[1]["toolpack_path"]
    assert calls[0]["output_format"] == calls[1]["output_format"]


def test_runtime_fails_closed_without_approved_lockfile(tmp_path: Path) -> None:
    toolpack = write_demo_toolpack(tmp_path)
    with pytest.raises(SystemExit) as exc:
        run_mcp_serve(
            tools_path=None,
            toolpack_path=str(toolpack),
            toolsets_path=None,
            toolset_name=None,
            policy_path=None,
            lockfile_path=None,
            base_url=None,
            auth_header=None,
            audit_log=None,
            dry_run=True,
            confirmation_store_path=str(tmp_path / "confirm.db"),
            allow_private_cidrs=[],
            allow_redirects=False,
            verbose=False,
            unsafe_no_lockfile=False,
        )
    assert exc.value.code == 1


def test_runtime_can_run_in_explicit_unsafe_mode(tmp_path: Path) -> None:
    toolpack = write_demo_toolpack(tmp_path)
    with patch("caskmcp.mcp.server.run_mcp_server") as mock_run:
        run_mcp_serve(
            tools_path=None,
            toolpack_path=str(toolpack),
            toolsets_path=None,
            toolset_name=None,
            policy_path=None,
            lockfile_path=None,
            base_url=None,
            auth_header=None,
            audit_log=None,
            dry_run=True,
            confirmation_store_path=str(tmp_path / "confirm.db"),
            allow_private_cidrs=[],
            allow_redirects=False,
            verbose=False,
            unsafe_no_lockfile=True,
        )
    assert mock_run.call_count == 1


def test_bundle_excludes_sensitive_runtime_state(tmp_path: Path) -> None:
    toolpack_file = write_demo_toolpack(tmp_path)
    root = toolpack_file.parent
    lockfile = root / "lockfile" / "caskmcp.lock.pending.yaml"
    manager = LockfileManager(lockfile)
    manager.load()
    manager.approve_all("tests")
    manager.save()

    (root / "auth").mkdir(parents=True, exist_ok=True)
    (root / "auth" / "storage_state.json").write_text('{"cookies":[]}')
    (root / ".caskmcp").mkdir(parents=True, exist_ok=True)
    (root / ".caskmcp" / "state").mkdir(parents=True, exist_ok=True)
    (root / ".caskmcp" / "state" / "approval_signing.key").write_text("secret")
    (root / "state").mkdir(parents=True, exist_ok=True)
    (root / "state" / "confirmations.db").write_text("secret")

    bundle_path = tmp_path / "bundle.zip"
    runner = CliRunner()
    snapshot = runner.invoke(
        cli,
        ["approve", "snapshot", "--lockfile", str(lockfile)],
    )
    assert snapshot.exit_code == 0

    result = runner.invoke(
        cli,
        ["bundle", "--toolpack", str(toolpack_file), "--out", str(bundle_path)],
    )
    assert result.exit_code == 0

    with zipfile.ZipFile(bundle_path, "r") as zf:
        names = set(zf.namelist())
    assert "BUNDLE_MANIFEST.json" in names
    assert "auth/storage_state.json" not in names
    assert "state/confirmations.db" not in names
    assert ".caskmcp/state/approval_signing.key" not in names
