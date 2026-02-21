"""Tests for interactive init and config flows."""

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


class TestInitFlow:
    """init_flow() prompts for directory and shows plan."""

    def test_shows_plan_with_default_directory(self, mock_console: Console) -> None:
        from caskmcp.ui.flows.init import init_flow

        with (
            patch("caskmcp.ui.flows.init.err_console", mock_console),
            patch("caskmcp.ui.flows.init.confirm", return_value=True),
            patch("caskmcp.cli.init.run_init"),
        ):
            init_flow(directory=".")

        output = mock_console.file.getvalue()  # type: ignore[attr-defined]
        assert "Will run" in output
        assert "cask init -d ." in output

    def test_shows_success_after_init(self, mock_console: Console) -> None:
        from caskmcp.ui.flows.init import init_flow

        with (
            patch("caskmcp.ui.flows.init.err_console", mock_console),
            patch("caskmcp.ui.flows.init.confirm", return_value=True),
            patch("caskmcp.cli.init.run_init"),
        ):
            init_flow(directory="/my/project")

        output = mock_console.file.getvalue()  # type: ignore[attr-defined]
        assert "Cask initialized" in output

    def test_aborts_on_decline(self, mock_console: Console) -> None:
        from caskmcp.ui.flows.init import init_flow

        with (
            patch("caskmcp.ui.flows.init.err_console", mock_console),
            patch("caskmcp.ui.flows.init.confirm", return_value=False),
            patch("caskmcp.cli.init.run_init") as mock_run,
        ):
            init_flow(directory=".")
            mock_run.assert_not_called()

    def test_prompts_for_directory_when_none(self, mock_console: Console) -> None:
        from caskmcp.ui.flows.init import init_flow

        with (
            patch("caskmcp.ui.flows.init.err_console", mock_console),
            patch("caskmcp.ui.flows.init.input_text", return_value="/some/dir"),
            patch("caskmcp.ui.flows.init.confirm", return_value=True),
            patch("caskmcp.cli.init.run_init"),
        ):
            init_flow()

        output = mock_console.file.getvalue()  # type: ignore[attr-defined]
        assert "cask init -d /some/dir" in output

    def test_handles_init_failure(self, mock_console: Console) -> None:
        from caskmcp.ui.flows.init import init_flow

        with (
            patch("caskmcp.ui.flows.init.err_console", mock_console),
            patch("caskmcp.ui.flows.init.confirm", return_value=True),
            patch("caskmcp.cli.init.run_init", side_effect=RuntimeError("boom")),
        ):
            init_flow(directory=".")

        output = mock_console.file.getvalue()  # type: ignore[attr-defined]
        assert "Init failed" in output


class TestConfigFlow:
    """config_flow() generates config snippets with guidance."""

    def test_shows_plan(self, tmp_path: Path, mock_console: Console) -> None:
        from caskmcp.ui.flows.config import config_flow

        tp = tmp_path / "toolpacks" / "api"
        tp.mkdir(parents=True)
        (tp / "toolpack.yaml").write_text("name: api")

        with (
            patch("caskmcp.ui.flows.config.err_console", mock_console),
            patch(
                "caskmcp.ui.flows.config.select_one",
                return_value="Claude Code",
            ),
            patch("caskmcp.cli.config.run_config"),
        ):
            config_flow(root=tmp_path)

        output = mock_console.file.getvalue()  # type: ignore[attr-defined]
        assert "Will run" in output
        assert "cask config" in output

    def test_shows_error_when_no_toolpacks(
        self, tmp_path: Path, mock_console: Console
    ) -> None:
        from caskmcp.ui.flows.config import config_flow

        with patch("caskmcp.ui.flows.config.err_console", mock_console):
            config_flow(root=tmp_path)

        output = mock_console.file.getvalue()  # type: ignore[attr-defined]
        assert "No toolpacks found" in output

    def test_shows_target_path_for_claude_desktop(
        self, mock_console: Console
    ) -> None:
        from caskmcp.ui.flows.config import config_flow

        with (
            patch("caskmcp.ui.flows.config.err_console", mock_console),
            patch(
                "caskmcp.ui.flows.config.select_one",
                return_value="Claude Desktop",
            ),
            patch("caskmcp.cli.config.run_config"),
        ):
            config_flow(toolpack_path="/some/toolpack.yaml")

        output = mock_console.file.getvalue()  # type: ignore[attr-defined]
        assert "Target config file" in output

    def test_codex_format_selected_for_codex_client(
        self, mock_console: Console
    ) -> None:
        from caskmcp.ui.flows.config import config_flow

        with (
            patch("caskmcp.ui.flows.config.err_console", mock_console),
            patch("caskmcp.ui.flows.config.select_one", return_value="Codex"),
            patch("caskmcp.cli.config.run_config") as mock_run_config,
        ):
            config_flow(toolpack_path="/some/toolpack.yaml")

        # Check that run_config was called with fmt="codex"
        mock_run_config.assert_called_once_with(
            toolpack_path="/some/toolpack.yaml", fmt="codex"
        )


class TestFlowRegistrationPhase4:
    """Init flow is registered in INTERACTIVE_COMMANDS."""

    def test_init_registered(self) -> None:
        from caskmcp.ui.flows import INTERACTIVE_COMMANDS

        assert "init" in INTERACTIVE_COMMANDS
