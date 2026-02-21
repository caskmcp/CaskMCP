"""Tests for the Ship Secure Agent flow."""

from __future__ import annotations

from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest
from rich.console import Console

from caskmcp.ui.console import CASK_THEME


@pytest.fixture
def mock_console() -> Console:
    return Console(file=StringIO(), force_terminal=False, theme=CASK_THEME)


class TestShipFlowStageCapture:
    """Stage 1: Capture."""

    def test_uses_existing_toolpack_when_available(
        self, tmp_path: Path, mock_console: Console
    ) -> None:
        from caskmcp.ui.flows.ship import _stage_capture

        tp = tmp_path / "toolpacks" / "api"
        tp.mkdir(parents=True)
        (tp / "toolpack.yaml").write_text("name: api")

        with (
            patch("caskmcp.ui.flows.ship.err_console", mock_console),
            patch("caskmcp.ui.flows.ship.confirm", return_value=True),
        ):
            result = _stage_capture(root=tmp_path, verbose=False)

        assert result is not None
        assert "toolpack.yaml" in result

    def test_returns_none_on_empty_url(self, tmp_path: Path, mock_console: Console) -> None:
        from caskmcp.ui.flows.ship import _stage_capture

        with (
            patch("caskmcp.ui.flows.ship.err_console", mock_console),
            # No existing toolpacks, so it prompts
            patch("caskmcp.ui.flows.ship.input_text", return_value=""),
        ):
            result = _stage_capture(root=tmp_path, verbose=False)

        assert result is None

    def test_shows_plan_before_capture(self, tmp_path: Path, mock_console: Console) -> None:
        from caskmcp.ui.flows.ship import _stage_capture

        with (
            patch("caskmcp.ui.flows.ship.err_console", mock_console),
            patch(
                "caskmcp.ui.flows.ship.input_text",
                side_effect=["https://api.example.com", "api.example.com", "test"],
            ),
            patch("caskmcp.ui.flows.ship.confirm", return_value=False),
        ):
            _stage_capture(root=tmp_path, verbose=False)

        output = mock_console.file.getvalue()  # type: ignore[attr-defined]
        assert "Will run" in output
        assert "cask mint" in output


class TestShipFlowStageServe:
    """Stage 6: Serve shows command."""

    def test_shows_serve_command(self, mock_console: Console) -> None:
        from caskmcp.ui.flows.ship import _stage_serve

        with patch("caskmcp.ui.flows.ship.err_console", mock_console):
            _stage_serve(toolpack_path="/my/toolpack.yaml")

        output = mock_console.file.getvalue()  # type: ignore[attr-defined]
        assert "cask serve --toolpack /my/toolpack.yaml" in output
        assert "Ctrl+C" in output


class TestShipFlowStageMonitor:
    """Stage 7: Monitor shows CI commands."""

    def test_shows_ci_commands(self, mock_console: Console) -> None:
        from caskmcp.ui.flows.ship import _stage_monitor

        with patch("caskmcp.ui.flows.ship.err_console", mock_console):
            _stage_monitor(
                toolpack_path="/my/toolpack.yaml",
                lockfile_path="/my/lockfile.yaml",
            )

        output = mock_console.file.getvalue()  # type: ignore[attr-defined]
        assert "cask gate check" in output
        assert "cask verify" in output
        assert "cask drift" in output
        assert "CI" in output


class TestShipFlowStageSnapshot:
    """Stage 3: Snapshot."""

    def test_calls_snapshot_on_confirm(self, mock_console: Console) -> None:
        from caskmcp.ui.flows.ship import _stage_snapshot

        with (
            patch("caskmcp.ui.flows.ship.err_console", mock_console),
            patch("caskmcp.ui.flows.ship.confirm", return_value=True),
            patch("caskmcp.ui.runner.run_gate_snapshot", return_value="/snap"),
        ):
            result = _stage_snapshot(
                lockfile_path="/my/lockfile.yaml",
                root=Path(".caskmcp"),
            )

        assert result is True
        output = mock_console.file.getvalue()  # type: ignore[attr-defined]
        assert "Baseline snapshot created" in output

    def test_returns_false_on_decline(self, mock_console: Console) -> None:
        from caskmcp.ui.flows.ship import _stage_snapshot

        with (
            patch("caskmcp.ui.flows.ship.err_console", mock_console),
            patch("caskmcp.ui.flows.ship.confirm", return_value=False),
        ):
            result = _stage_snapshot(
                lockfile_path="/my/lockfile.yaml",
                root=Path(".caskmcp"),
            )

        assert result is False


class TestShipFlowProgress:
    """Progress indicator works correctly."""

    def test_shows_progress_stages(self, mock_console: Console) -> None:
        from caskmcp.ui.flows.ship import _show_progress

        with patch("caskmcp.ui.flows.ship.err_console", mock_console):
            _show_progress(current_stage=2, done_stages={0, 1})

        output = mock_console.file.getvalue()  # type: ignore[attr-defined]
        assert "Capture API surface" in output
        assert "Review" in output
        assert "Materialize baseline" in output
