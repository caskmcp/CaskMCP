"""Tests for actionable error messages when serve fails on lockfile issues.

Error messages must include concrete commands with actual paths so users
can copy-paste to fix the problem.
"""

import json
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from caskmcp.utils.schema_version import CURRENT_SCHEMA_VERSION


def _write_toolpack(
    tmp: Path,
    *,
    pending_ref: bool = True,
    pending_on_disk: bool = False,
) -> Path:
    """Create a minimal toolpack structure and return toolpack.yaml path.

    Args:
        pending_ref: Whether toolpack.yaml references a pending lockfile path.
        pending_on_disk: Whether the pending lockfile actually exists on disk.
    """
    artifact_dir = tmp / "artifact"
    artifact_dir.mkdir()
    lockfile_dir = tmp / "lockfile"
    lockfile_dir.mkdir()

    # Minimal tools.json
    tools = [
        {
            "name": "get_users",
            "description": "List users",
            "inputSchema": {"type": "object", "properties": {}},
        }
    ]
    (artifact_dir / "tools.json").write_text(json.dumps(tools))

    # Minimal policy
    (artifact_dir / "policy.yaml").write_text(
        yaml.dump({"version": "1.0.0", "schema_version": CURRENT_SCHEMA_VERSION, "rules": []})
    )

    # Minimal toolsets
    (artifact_dir / "toolsets.yaml").write_text(
        yaml.dump({
            "schema_version": CURRENT_SCHEMA_VERSION,
            "toolsets": {"readonly": {"tools": ["get_users"]}},
        })
    )

    # Minimal baseline
    (artifact_dir / "baseline.json").write_text(json.dumps({"tools": {}}))

    lockfiles: dict[str, str] = {}
    if pending_ref:
        lockfiles["pending"] = "lockfile/caskmcp.lock.pending.yaml"
        if pending_on_disk:
            (lockfile_dir / "caskmcp.lock.pending.yaml").write_text(
                yaml.dump({
                    "schema_version": CURRENT_SCHEMA_VERSION,
                    "tools": {"get_users": {"status": "pending"}},
                })
            )

    toolpack = {
        "schema_version": CURRENT_SCHEMA_VERSION,
        "version": "1.0.0",
        "toolpack_id": "tp_test_001",
        "created_at": "2025-01-01T00:00:00Z",
        "capture_id": "cap_test_001",
        "artifact_id": "art_test_001",
        "scope": "first_party_only",
        "origin": {"start_url": "https://api.example.com", "name": "test"},
        "paths": {
            "tools": "artifact/tools.json",
            "toolsets": "artifact/toolsets.yaml",
            "policy": "artifact/policy.yaml",
            "baseline": "artifact/baseline.json",
            "lockfiles": lockfiles,
        },
    }
    toolpack_path = tmp / "toolpack.yaml"
    toolpack_path.write_text(yaml.dump(toolpack))

    return toolpack_path


def _run_serve_and_capture_errors(toolpack_path: Path, tmp_path: Path) -> str:
    """Run serve and capture all error output."""
    from caskmcp.cli.mcp import run_mcp_serve

    with pytest.raises(SystemExit):
        with patch("click.echo") as mock_echo:
            run_mcp_serve(
                tools_path=None,
                toolpack_path=str(toolpack_path),
                toolsets_path=None,
                toolset_name=None,
                policy_path=None,
                lockfile_path=None,
                base_url=None,
                auth_header=None,
                audit_log=None,
                dry_run=False,
                confirmation_store_path=str(tmp_path / "confirms.json"),
                allow_private_cidrs=[],
                allow_redirects=False,
                verbose=False,
                unsafe_no_lockfile=False,
            )

    error_calls = [
        call.args[0]
        for call in mock_echo.call_args_list
        if call.kwargs.get("err", False)
    ]
    return "\n".join(error_calls)


class TestServeErrorMessages:
    """Error messages should include concrete commands with actual paths."""

    def test_pending_ref_no_file_includes_gate_allow(self, tmp_path: Path) -> None:
        """When toolpack references pending but file missing, error shows gate allow."""
        toolpack_path = _write_toolpack(
            tmp_path, pending_ref=True, pending_on_disk=False,
        )
        error_text = _run_serve_and_capture_errors(toolpack_path, tmp_path)

        assert "cask gate allow" in error_text, (
            f"Error should include 'cask gate allow' command, got:\n{error_text}"
        )
        assert "cask gate check" in error_text, (
            f"Error should include 'cask gate check' command, got:\n{error_text}"
        )
        assert "cask serve" in error_text, (
            f"Error should include 'cask serve' command, got:\n{error_text}"
        )

    def test_pending_ref_no_file_includes_actual_paths(self, tmp_path: Path) -> None:
        """Error should include actual file paths, not placeholders."""
        toolpack_path = _write_toolpack(
            tmp_path, pending_ref=True, pending_on_disk=False,
        )
        error_text = _run_serve_and_capture_errors(toolpack_path, tmp_path)

        assert "caskmcp.lock.pending.yaml" in error_text, (
            f"Error should reference the pending lockfile path, got:\n{error_text}"
        )
        assert "toolpack.yaml" in error_text, (
            f"Error should reference the toolpack path, got:\n{error_text}"
        )

    def test_no_lockfile_at_all_error_is_actionable(self, tmp_path: Path) -> None:
        """When no lockfile exists at all, error should guide user to create one."""
        toolpack_path = _write_toolpack(
            tmp_path, pending_ref=False, pending_on_disk=False,
        )
        error_text = _run_serve_and_capture_errors(toolpack_path, tmp_path)

        assert "cask gate allow" in error_text, (
            f"Error should mention 'cask gate allow', got:\n{error_text}"
        )
        assert "cask serve" in error_text, (
            f"Error should mention 'cask serve' next step, got:\n{error_text}"
        )
