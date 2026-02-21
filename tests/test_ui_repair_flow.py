"""Tests for the interactive repair flow."""

from __future__ import annotations

from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest
from rich.console import Console

from caskmcp.ui.console import CASK_THEME
from caskmcp.ui.runner import DoctorCheck, DoctorResult


@pytest.fixture
def mock_console() -> Console:
    return Console(file=StringIO(), force_terminal=False, theme=CASK_THEME)


class TestRepairFlowDiagnosis:
    """repair_flow() runs doctor checks and classifies failures."""

    def test_shows_diagnosis_heading(self, mock_console: Console) -> None:
        from caskmcp.ui.flows.repair import repair_flow

        with (
            patch("caskmcp.ui.flows.repair.err_console", mock_console),
            # Decline running doctor — heading should still show
            patch("caskmcp.ui.flows.repair.confirm", return_value=False),
        ):
            repair_flow(toolpack_path="/some/toolpack.yaml", root=Path(".caskmcp"))

        output = mock_console.file.getvalue()  # type: ignore[attr-defined]
        assert "Repair" in output

    def test_shows_all_healthy_when_no_failures(self, mock_console: Console) -> None:
        from caskmcp.ui.flows.repair import repair_flow

        result = DoctorResult(
            checks=[
                DoctorCheck("tools.json", True, "/path/tools.json"),
                DoctorCheck("lockfile", True, "/path/lockfile"),
            ],
            runtime_mode="local",
        )

        with (
            patch("caskmcp.ui.flows.repair.err_console", mock_console),
            patch("caskmcp.ui.runner.run_doctor_checks", return_value=result),
            # confirm "Run doctor?" -> True, then _has_pending_tools returns False
            patch("caskmcp.ui.flows.repair.confirm", return_value=True),
            patch("caskmcp.ui.flows.repair._has_pending_tools", return_value=False),
        ):
            repair_flow(toolpack_path="/some/toolpack.yaml", root=Path(".caskmcp"))

        output = mock_console.file.getvalue()  # type: ignore[attr-defined]
        assert "All checks passed" in output

    def test_classifies_missing_artifacts(self, mock_console: Console) -> None:
        from caskmcp.ui.flows.repair import repair_flow

        result = DoctorResult(
            checks=[
                DoctorCheck("tools.json", False, "tools.json missing: /p/tools.json"),
                DoctorCheck("lockfile", True, "/path/lockfile"),
            ],
            runtime_mode="local",
        )

        with (
            patch("caskmcp.ui.flows.repair.err_console", mock_console),
            patch("caskmcp.ui.runner.run_doctor_checks", return_value=result),
            patch("caskmcp.ui.flows.repair.confirm", return_value=True),
            patch("caskmcp.ui.flows.repair._has_pending_tools", return_value=False),
        ):
            repair_flow(toolpack_path="/some/toolpack.yaml", root=Path(".caskmcp"))

        output = mock_console.file.getvalue()  # type: ignore[attr-defined]
        assert "missing" in output.lower()

    def test_classifies_digest_mismatch(self, mock_console: Console) -> None:
        from caskmcp.ui.flows.repair import repair_flow

        result = DoctorResult(
            checks=[
                DoctorCheck("tools.json", True, "/p/tools.json"),
                DoctorCheck("artifacts digest", False, "lockfile artifacts digest mismatch; re-run cask gate sync"),
            ],
            runtime_mode="local",
        )

        with (
            patch("caskmcp.ui.flows.repair.err_console", mock_console),
            patch("caskmcp.ui.runner.run_doctor_checks", return_value=result),
            patch("caskmcp.ui.flows.repair.confirm", return_value=True),
            patch("caskmcp.ui.flows.repair._has_pending_tools", return_value=False),
        ):
            repair_flow(toolpack_path="/some/toolpack.yaml", root=Path(".caskmcp"))

        output = mock_console.file.getvalue()  # type: ignore[attr-defined]
        assert "cask gate sync" in output


class TestRepairFlowSuggestedFixes:
    """repair_flow() suggests specific fix commands."""

    def test_suggests_gate_sync_for_missing_lockfile(self, mock_console: Console) -> None:
        from caskmcp.ui.flows.repair import repair_flow

        result = DoctorResult(
            checks=[
                DoctorCheck("lockfile", False, "missing; run cask gate sync"),
            ],
            runtime_mode="local",
        )

        with (
            patch("caskmcp.ui.flows.repair.err_console", mock_console),
            patch("caskmcp.ui.runner.run_doctor_checks", return_value=result),
            patch("caskmcp.ui.flows.repair.confirm", return_value=True),
            patch("caskmcp.ui.flows.repair._has_pending_tools", return_value=False),
        ):
            repair_flow(toolpack_path="/some/toolpack.yaml", root=Path(".caskmcp"))

        output = mock_console.file.getvalue()  # type: ignore[attr-defined]
        assert "cask gate sync" in output

    def test_suggests_recapture_for_missing_tools(self, mock_console: Console) -> None:
        from caskmcp.ui.flows.repair import repair_flow

        result = DoctorResult(
            checks=[
                DoctorCheck("tools.json", False, "tools.json missing: /p/tools.json"),
            ],
            runtime_mode="local",
        )

        with (
            patch("caskmcp.ui.flows.repair.err_console", mock_console),
            patch("caskmcp.ui.runner.run_doctor_checks", return_value=result),
            patch("caskmcp.ui.flows.repair.confirm", return_value=True),
            patch("caskmcp.ui.flows.repair._has_pending_tools", return_value=False),
        ):
            repair_flow(toolpack_path="/some/toolpack.yaml", root=Path(".caskmcp"))

        output = mock_console.file.getvalue()  # type: ignore[attr-defined]
        assert "cask mint" in output

    def test_suggests_docker_for_missing_docker(self, mock_console: Console) -> None:
        from caskmcp.ui.flows.repair import repair_flow

        result = DoctorResult(
            checks=[
                DoctorCheck("docker", False, "docker not available; install Docker or use --runtime local"),
            ],
            runtime_mode="container",
        )

        with (
            patch("caskmcp.ui.flows.repair.err_console", mock_console),
            patch("caskmcp.ui.runner.run_doctor_checks", return_value=result),
            patch("caskmcp.ui.flows.repair.confirm", return_value=True),
            patch("caskmcp.ui.flows.repair._has_pending_tools", return_value=False),
        ):
            repair_flow(toolpack_path="/some/toolpack.yaml", root=Path(".caskmcp"))

        output = mock_console.file.getvalue()  # type: ignore[attr-defined]
        assert "docker" in output.lower() or "--runtime local" in output


class TestRepairFlowPrompts:
    """repair_flow() prompts for toolpack when not provided."""

    def test_prompts_for_toolpack_when_missing(
        self, tmp_path: Path, mock_console: Console
    ) -> None:
        from caskmcp.ui.flows.repair import repair_flow

        tp = tmp_path / "toolpacks" / "api"
        tp.mkdir(parents=True)
        (tp / "toolpack.yaml").write_text("name: api")

        result = DoctorResult(
            checks=[DoctorCheck("test", True, "ok")],
            runtime_mode="local",
        )

        with (
            patch("caskmcp.ui.flows.repair.err_console", mock_console),
            patch("caskmcp.ui.runner.run_doctor_checks", return_value=result),
            patch("caskmcp.ui.flows.repair.confirm", return_value=True),
            patch("caskmcp.ui.flows.repair._has_pending_tools", return_value=False),
        ):
            repair_flow(root=tmp_path)

    def test_shows_error_when_no_toolpacks(
        self, tmp_path: Path, mock_console: Console
    ) -> None:
        from caskmcp.ui.flows.repair import repair_flow

        with patch("caskmcp.ui.flows.repair.err_console", mock_console):
            repair_flow(root=tmp_path)

        output = mock_console.file.getvalue()  # type: ignore[attr-defined]
        assert "No toolpacks found" in output


class TestRepairFlowJumpToGate:
    """repair_flow() offers to jump to gate review when pending tools found."""

    def test_offers_gate_review_on_pending(self, mock_console: Console) -> None:
        from caskmcp.ui.flows.repair import repair_flow

        result = DoctorResult(
            checks=[
                DoctorCheck("lockfile", True, "/path/lockfile"),
            ],
            runtime_mode="local",
        )

        with (
            patch("caskmcp.ui.flows.repair.err_console", mock_console),
            patch("caskmcp.ui.runner.run_doctor_checks", return_value=result),
            # First confirm: "Run doctor?" -> yes
            # Second confirm: "Jump to review?" -> no
            patch("caskmcp.ui.flows.repair.confirm", side_effect=[True, False]),
            patch("caskmcp.ui.flows.repair._has_pending_tools", return_value=True),
        ):
            repair_flow(toolpack_path="/some/toolpack.yaml", root=Path(".caskmcp"))

        output = mock_console.file.getvalue()  # type: ignore[attr-defined]
        assert "pending" in output.lower()


class TestRepairFlowRegistration:
    """Repair flow is accessible from the module."""

    def test_repair_flow_importable(self) -> None:
        from caskmcp.ui.flows.repair import repair_flow

        assert callable(repair_flow)
