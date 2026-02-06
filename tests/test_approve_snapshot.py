"""Tests for approval snapshot materialization."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from caskmcp.cli.main import cli
from tests.helpers import load_yaml, write_demo_toolpack


def test_approve_materializes_snapshot(tmp_path: Path) -> None:
    toolpack_file = write_demo_toolpack(tmp_path)
    lockfile_path = toolpack_file.parent / "lockfile" / "caskmcp.lock.pending.yaml"

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["approve", "tool", "--all", "--lockfile", str(lockfile_path)],
    )

    assert result.exit_code == 0
    lockfile = load_yaml(lockfile_path)
    assert "baseline_snapshot_dir" in lockfile
    assert "baseline_snapshot_digest" in lockfile

    snapshot_dir = toolpack_file.parent / lockfile["baseline_snapshot_dir"]
    assert snapshot_dir.exists()
    digests_path = snapshot_dir.parent / "digests.json"
    assert digests_path.exists()
