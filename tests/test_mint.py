"""Tests for mint orchestration."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import yaml
from click.testing import CliRunner

from mcpmint.cli.approve import ApprovalSyncResult
from mcpmint.cli.compile import CompileResult
from mcpmint.cli.main import cli
from mcpmint.cli.mint import build_mcp_config_snippet, run_mint
from mcpmint.models.capture import CaptureSession, CaptureSource, HttpExchange, HTTPMethod
from mcpmint.models.scope import Scope


def _write_artifact_fixture(tmp_path: Path) -> Path:
    artifact_dir = tmp_path / "artifacts" / "art_demo"
    artifact_dir.mkdir(parents=True)
    (artifact_dir / "tools.json").write_text(
        '{"version":"1.0.0","schema_version":"1.0","actions":[]}'
    )
    (artifact_dir / "toolsets.yaml").write_text(
        "version: '1.0.0'\nschema_version: '1.0'\ntoolsets: {readonly: {actions: []}}\n"
    )
    (artifact_dir / "policy.yaml").write_text(
        "version: '1.0.0'\nschema_version: '1.0'\nname: Demo\ndefault_action: allow\nrules: []\n"
    )
    (artifact_dir / "baseline.json").write_text("{}")
    (artifact_dir / "contract.yaml").write_text("openapi: 3.1.0\n")
    (artifact_dir / "contract.json").write_text('{"openapi":"3.1.0"}')
    return artifact_dir


class TestMint:
    def test_run_mint_creates_toolpack(self, tmp_path: Path, capsys) -> None:
        artifact_dir = _write_artifact_fixture(tmp_path)
        session = CaptureSession(
            id="cap_demo",
            name="Demo Capture",
            source=CaptureSource.PLAYWRIGHT,
            allowed_hosts=["api.example.com"],
            created_at=datetime(2026, 2, 5, tzinfo=UTC),
            exchanges=[
                HttpExchange(
                    url="https://api.example.com/users",
                    method=HTTPMethod.GET,
                    host="api.example.com",
                    path="/users",
                )
            ],
        )

        compile_result = CompileResult(
            artifact_id="art_demo",
            output_path=artifact_dir,
            scope=Scope(name="agent_safe_readonly"),
            endpoint_count=1,
            generated_at=session.created_at,
            artifacts_created=(
                ("Tool Manifest", artifact_dir / "tools.json"),
                ("Toolsets", artifact_dir / "toolsets.yaml"),
                ("Policy", artifact_dir / "policy.yaml"),
                ("Baseline", artifact_dir / "baseline.json"),
            ),
            tools_path=artifact_dir / "tools.json",
            toolsets_path=artifact_dir / "toolsets.yaml",
            policy_path=artifact_dir / "policy.yaml",
            baseline_path=artifact_dir / "baseline.json",
            contract_yaml_path=artifact_dir / "contract.yaml",
            contract_json_path=artifact_dir / "contract.json",
        )

        capture_calls: dict[str, object] = {}

        class FakePlaywrightCapture:
            def __init__(self, allowed_hosts: list[str], headless: bool = False) -> None:
                capture_calls["allowed_hosts"] = allowed_hosts
                capture_calls["headless"] = headless

            async def capture(self, **kwargs):
                capture_calls["capture_kwargs"] = kwargs
                return session

        with patch(
            "mcpmint.core.capture.playwright_capture.PlaywrightCapture",
            FakePlaywrightCapture,
        ), patch(
            "mcpmint.cli.mint.compile_capture_session",
            return_value=compile_result,
        ), patch(
            "mcpmint.cli.mint.sync_lockfile",
            return_value=ApprovalSyncResult(
                lockfile_path=tmp_path / "dummy.lock.yaml",
                artifacts_digest="abc123",
                changes={"new": [], "modified": [], "removed": [], "unchanged": []},
                has_pending=True,
                pending_count=2,
            ),
        ) as mock_sync:
            run_mint(
                start_url="https://app.example.com",
                allowed_hosts=["api.example.com"],
                name="Demo",
                scope_name="agent_safe_readonly",
                headless=True,
                script_path=None,
                duration_seconds=30,
                output_root=str(tmp_path),
                deterministic=True,
                print_mcp_config=True,
                verbose=False,
            )

        out = capsys.readouterr().out
        assert "Mint complete:" in out
        assert "mcpmint run --toolpack" in out
        assert "mcpmint approve tool --all --toolset readonly" in out

        toolpack_files = list((tmp_path / "toolpacks").glob("*/toolpack.yaml"))
        assert len(toolpack_files) == 1
        with open(toolpack_files[0]) as f:
            payload = yaml.safe_load(f)
        assert payload["schema_version"] == "1.0"
        assert payload["capture_id"] == "cap_demo"
        assert payload["paths"]["tools"] == "artifact/tools.json"
        assert payload["paths"]["lockfiles"]["pending"] == "lockfile/mcpmint.lock.pending.yaml"

        assert capture_calls["headless"] is True
        assert capture_calls["capture_kwargs"]["duration_seconds"] == 30

        assert mock_sync.call_count == 1
        sync_kwargs = mock_sync.call_args.kwargs
        assert sync_kwargs["capture_id"] == "cap_demo"
        assert sync_kwargs["scope"] == "agent_safe_readonly"
        assert sync_kwargs["tools_path"].endswith("artifact/tools.json")

    def test_build_mcp_config_snippet(self, tmp_path: Path) -> None:
        snippet = build_mcp_config_snippet(
            toolpack_path=tmp_path / "toolpack.yaml",
            server_name="demo",
        )
        assert '"command": "mcpmint"' in snippet
        assert '"run"' in snippet
        assert '"--toolpack"' in snippet

    def test_mint_cli_wires_arguments(self) -> None:
        runner = CliRunner()
        with patch("mcpmint.cli.mint.run_mint") as mock_run:
            result = runner.invoke(
                cli,
                [
                    "mint",
                    "https://app.example.com",
                    "-a",
                    "api.example.com",
                    "--duration",
                    "20",
                    "--print-mcp-config",
                ],
            )

        assert result.exit_code == 0
        kwargs = mock_run.call_args.kwargs
        assert kwargs["start_url"] == "https://app.example.com"
        assert kwargs["allowed_hosts"] == ["api.example.com"]
        assert kwargs["duration_seconds"] == 20
        assert kwargs["print_mcp_config"] is True
        assert kwargs["runtime_mode"] == "local"
        assert kwargs["runtime_build"] is False
        assert kwargs["runtime_tag"] is None
        assert kwargs["runtime_version_pin"] is None
