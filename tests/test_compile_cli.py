"""CLI tests for compile command output-format surface."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from click.testing import CliRunner

from caskmcp.cli.main import cli
from caskmcp.models.capture import CaptureSession, CaptureSource, HttpExchange, HTTPMethod
from caskmcp.storage import Storage


def _write_capture(tmp_path: Path) -> CaptureSession:
    session = CaptureSession(
        id="cap_compile",
        name="Compile Demo",
        source=CaptureSource.HAR,
        created_at=datetime(2026, 2, 6, tzinfo=UTC),
        allowed_hosts=["api.example.com"],
        exchanges=[
            HttpExchange(
                url="https://api.example.com/api/users",
                method=HTTPMethod.GET,
                host="api.example.com",
                path="/api/users",
                response_status=200,
                response_content_type="application/json",
            )
        ],
    )
    storage = Storage(base_path=tmp_path / ".caskmcp")
    storage.save_capture(session)
    return session


def test_compile_rejects_mcp_python_format() -> None:
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["compile", "--capture", "cap_dummy", "--format", "mcp-python"],
    )

    assert result.exit_code != 0
    assert "Invalid value for '--format' / '-f'" in result.stderr


def test_compile_manifest_format_still_works(tmp_path: Path, monkeypatch) -> None:
    session = _write_capture(tmp_path)
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        cli,
        [
            "compile",
            "--capture",
            session.id,
            "--scope",
            "first_party_only",
            "--format",
            "manifest",
            "--output",
            ".caskmcp/artifacts",
        ],
    )

    assert result.exit_code == 0
    assert "Compile complete:" in result.stdout
    artifacts_root = tmp_path / ".caskmcp" / "artifacts"
    artifact_dirs = [p for p in artifacts_root.iterdir() if p.is_dir()]
    assert artifact_dirs
    artifact_dir = artifact_dirs[0]
    assert (artifact_dir / "tools.json").exists()
    assert (artifact_dir / "toolsets.yaml").exists()
    assert (artifact_dir / "policy.yaml").exists()
    assert (artifact_dir / "baseline.json").exists()
