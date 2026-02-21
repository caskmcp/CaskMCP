"""Tests for caskmcp bundle command."""

from __future__ import annotations

import zipfile
from pathlib import Path

from click.testing import CliRunner

from caskmcp.cli.main import cli
from caskmcp.core.approval import LockfileManager
from tests.helpers import write_demo_toolpack


def test_bundle_contains_expected_files(tmp_path: Path) -> None:
    toolpack_file = write_demo_toolpack(tmp_path)
    lockfile_path = toolpack_file.parent / "lockfile" / "caskmcp.lock.pending.yaml"

    manager = LockfileManager(lockfile_path)
    manager.load()
    manager.approve_all()
    manager.save()

    runner = CliRunner()
    snapshot_result = runner.invoke(
        cli,
        ["gate", "snapshot", "--lockfile", str(lockfile_path)],
    )
    assert snapshot_result.exit_code == 0

    bundle_path = tmp_path / "bundle.zip"
    result = runner.invoke(
        cli,
        ["bundle", "--toolpack", str(toolpack_file), "--out", str(bundle_path)],
    )

    assert result.exit_code == 0
    assert result.stdout == ""
    assert bundle_path.exists()

    with zipfile.ZipFile(bundle_path, "r") as zf:
        names = zf.namelist()
    assert "toolpack.yaml" in names
    assert "plan.json" in names
    assert "plan.md" in names
    assert "client-config.json" in names
    assert "RUN.md" in names
    assert not any(name.startswith(".caskmcp/reports") for name in names)
