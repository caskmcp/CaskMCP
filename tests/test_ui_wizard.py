"""Tests for the wizard / quickstart flow."""

from __future__ import annotations

from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from rich.console import Console

from caskmcp.ui.console import CASK_THEME


@pytest.fixture
def mock_console() -> Console:
    return Console(file=StringIO(), force_terminal=False, theme=CASK_THEME)


class TestWizardLaunch:
    """Wizard launches on no-args + interactive, shows help otherwise."""

    def test_wizard_launches_when_interactive(self, mock_console: Console) -> None:
        from caskmcp.ui.flows.quickstart import wizard_flow

        with (
            patch("caskmcp.ui.flows.quickstart.err_console", mock_console),
            # Exit immediately
            patch("caskmcp.ui.flows.quickstart.select_one", return_value="exit"),
        ):
            wizard_flow(root=Path(".caskmcp"))

        output = mock_console.file.getvalue()  # type: ignore[attr-defined]
        # Should show branding
        assert "Cask" in output

    def test_shows_help_in_non_interactive_mode(self) -> None:
        """When --no-interactive is set, cask shows help instead of wizard."""
        runner = CliRunner()
        from caskmcp.cli.main import cli

        result = runner.invoke(cli, ["--no-interactive"])
        assert result.exit_code == 0
        # Help output should appear since non-interactive shows help
        assert "Usage" in result.output or "Commands" in result.output

    def test_help_flag_still_works(self) -> None:
        """--help is not intercepted by wizard."""
        runner = CliRunner()
        from caskmcp.cli.main import cli

        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "Usage" in result.output

    def test_version_flag_still_works(self) -> None:
        """--version is not intercepted by wizard."""
        runner = CliRunner()
        from caskmcp.cli.main import cli

        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0


class TestWizardMenu:
    """Wizard menu dispatches correctly."""

    def test_exit_returns_immediately(self, mock_console: Console) -> None:
        from caskmcp.ui.flows.quickstart import wizard_flow

        with (
            patch("caskmcp.ui.flows.quickstart.err_console", mock_console),
            patch("caskmcp.ui.flows.quickstart.select_one", return_value="exit"),
        ):
            wizard_flow(root=Path(".caskmcp"))

    def test_dispatches_to_doctor(self, mock_console: Console) -> None:
        from caskmcp.ui.flows.quickstart import wizard_flow

        call_count = {"n": 0}

        def mock_select(*_args, **_kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return "doctor"
            return "exit"

        with (
            patch("caskmcp.ui.flows.quickstart.err_console", mock_console),
            patch("caskmcp.ui.flows.quickstart.select_one", side_effect=mock_select),
            patch("caskmcp.ui.flows.doctor.err_console", mock_console),
            patch("caskmcp.ui.flows.doctor.find_toolpacks", return_value=[]),
            # confirm is lazily imported inside wizard_flow, patch at source
            patch("caskmcp.ui.prompts.confirm", return_value=False),
        ):
            wizard_flow(root=Path(".caskmcp"))

    def test_dispatches_to_init(self, mock_console: Console) -> None:
        from caskmcp.ui.flows.quickstart import wizard_flow

        call_count = {"n": 0}

        def mock_select(*_args, **_kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return "init"
            return "exit"

        with (
            patch("caskmcp.ui.flows.quickstart.err_console", mock_console),
            patch("caskmcp.ui.flows.quickstart.select_one", side_effect=mock_select),
            patch("caskmcp.ui.flows.init.err_console", mock_console),
            patch("caskmcp.ui.flows.init.input_text", return_value="."),
            patch("caskmcp.ui.flows.init.confirm", return_value=False),
            # confirm inside wizard_flow for "Return to menu?"
            patch("caskmcp.ui.prompts.confirm", return_value=False),
        ):
            wizard_flow(root=Path(".caskmcp"))


class TestWizardStatusSummary:
    """Wizard shows status summary on start."""

    def test_shows_toolpack_count(self, mock_console: Console, tmp_path: Path) -> None:
        from caskmcp.ui.flows.quickstart import wizard_flow

        # Create two toolpacks
        for name in ("api1", "api2"):
            tp = tmp_path / "toolpacks" / name
            tp.mkdir(parents=True)
            (tp / "toolpack.yaml").write_text(f"name: {name}")

        with (
            patch("caskmcp.ui.flows.quickstart.err_console", mock_console),
            patch("caskmcp.ui.flows.quickstart.select_one", return_value="exit"),
        ):
            wizard_flow(root=tmp_path)

        output = mock_console.file.getvalue()  # type: ignore[attr-defined]
        assert "2 toolpacks" in output


class TestQuickstartFlow:
    """Quickstart sub-flow collects inputs and shows plan."""

    def test_shows_plan_before_mint(self, mock_console: Console) -> None:
        from caskmcp.ui.flows.quickstart import _quickstart_flow

        with (
            patch("caskmcp.ui.flows.quickstart.err_console", mock_console),
            # input_text is lazily imported, patch at source
            patch(
                "caskmcp.ui.prompts.input_text",
                side_effect=["https://api.example.com", "api.example.com", ""],
            ),
            patch("caskmcp.ui.prompts.confirm", return_value=False),
        ):
            _quickstart_flow(root=Path(".caskmcp"), verbose=False)

        output = mock_console.file.getvalue()  # type: ignore[attr-defined]
        assert "Will run" in output
        assert "cask mint https://api.example.com" in output
        assert "-a api.example.com" in output

    def test_aborts_on_empty_url(self, mock_console: Console) -> None:
        from caskmcp.ui.flows.quickstart import _quickstart_flow

        with (
            patch("caskmcp.ui.flows.quickstart.err_console", mock_console),
            patch("caskmcp.ui.prompts.input_text", return_value=""),
        ):
            _quickstart_flow(root=Path(".caskmcp"), verbose=False)

        output = mock_console.file.getvalue()  # type: ignore[attr-defined]
        assert "URL is required" in output
