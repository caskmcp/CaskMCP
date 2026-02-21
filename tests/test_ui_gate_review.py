"""Tests for the interactive gate review flow."""

from __future__ import annotations

from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console

from caskmcp.core.approval.lockfile import ApprovalStatus, ToolApproval


def _make_tool(
    tool_id: str = "get_users",
    name: str = "get_users",
    risk_tier: str = "low",
    status: ApprovalStatus = ApprovalStatus.PENDING,
) -> ToolApproval:
    """Create a mock ToolApproval."""
    return ToolApproval(
        tool_id=tool_id,
        signature_id=f"GET:/api/{name}@api.example.com",
        name=name,
        method="GET",
        path=f"/api/{name}",
        host="api.example.com",
        risk_tier=risk_tier,
        status=status,
        toolsets=["default"],
    )


@pytest.fixture
def mock_console() -> Console:
    from caskmcp.ui.console import CASK_THEME

    return Console(file=StringIO(), force_terminal=False, theme=CASK_THEME)


class TestGateReviewNoLockfiles:
    """gate_review_flow shows error when no lockfiles found."""

    def test_no_lockfiles(self, mock_console: Console) -> None:
        from caskmcp.ui.flows.gate_review import gate_review_flow

        with patch("caskmcp.ui.flows.gate_review.err_console", mock_console):
            gate_review_flow(root_path="/nonexistent")

        output = mock_console.file.getvalue()  # type: ignore[attr-defined]
        assert "No lockfiles found" in output


class TestGateReviewNoPending:
    """When all tools are already reviewed, show success."""

    def test_no_pending_tools(self, mock_console: Console) -> None:
        from caskmcp.ui.flows.gate_review import gate_review_flow

        tools = [_make_tool(status=ApprovalStatus.APPROVED)]
        lockfile = MagicMock()
        lockfile.tools = {"get_users": tools[0]}

        with (
            patch("caskmcp.ui.flows.gate_review.err_console", mock_console),
            patch(
                "caskmcp.ui.flows.gate_review.load_lockfile_tools",
                return_value=(lockfile, tools),
            ),
        ):
            gate_review_flow(lockfile_path="/some/lockfile.yaml")

        output = mock_console.file.getvalue()  # type: ignore[attr-defined]
        assert "No pending tools" in output


class TestGateReviewDirectoryValidation:
    """gate_review_flow rejects directory paths."""

    def test_rejects_directory_path(self, tmp_path: Path, mock_console: Console) -> None:
        from caskmcp.ui.flows.gate_review import gate_review_flow

        with patch("caskmcp.ui.flows.gate_review.err_console", mock_console):
            gate_review_flow(lockfile_path=str(tmp_path))

        output = mock_console.file.getvalue()  # type: ignore[attr-defined]
        assert "Expected a file, got a directory" in output


class TestGateReviewCancel:
    """User can cancel the review."""

    def test_cancel_makes_no_changes(self, mock_console: Console) -> None:
        from caskmcp.ui.flows.gate_review import gate_review_flow

        tools = [_make_tool()]
        lockfile = MagicMock()

        with (
            patch("caskmcp.ui.flows.gate_review.err_console", mock_console),
            patch(
                "caskmcp.ui.flows.gate_review.load_lockfile_tools",
                return_value=(lockfile, tools),
            ),
            # select_one returns "cancel"
            patch("caskmcp.ui.flows.gate_review.select_one", return_value="cancel"),
            patch("caskmcp.ui.flows.gate_review.run_gate_approve") as mock_approve,
        ):
            gate_review_flow(lockfile_path="/some/lockfile.yaml")
            mock_approve.assert_not_called()


class TestGateReviewHighRiskRequiresTypedConfirm:
    """High-risk tools require per-tool typed APPROVE confirmation."""

    def test_high_risk_skipped_without_typed_confirm(self, mock_console: Console) -> None:
        from caskmcp.ui.flows.gate_review import gate_review_flow

        tools = [_make_tool(risk_tier="high", tool_id="delete_users", name="delete_users")]
        lockfile = MagicMock()

        with (
            patch("caskmcp.ui.flows.gate_review.err_console", mock_console),
            patch(
                "caskmcp.ui.flows.gate_review.load_lockfile_tools",
                return_value=(lockfile, tools),
            ),
            # Choose "approve_all"
            patch("caskmcp.ui.flows.gate_review.select_one", return_value="approve_all"),
            # confirm_typed returns False (user didn't type APPROVE)
            patch("caskmcp.ui.flows.gate_review.confirm_typed", return_value=False),
            # confirm for "proceed?" should not be reached since nothing to do
            patch("caskmcp.ui.flows.gate_review.confirm", return_value=True),
            patch("caskmcp.ui.flows.gate_review.run_gate_approve") as mock_approve,
        ):
            gate_review_flow(lockfile_path="/some/lockfile.yaml")
            # Should not have been called — the tool was skipped
            mock_approve.assert_not_called()


class TestGateReviewPlanFirst:
    """Review flow shows plan before executing."""

    def test_shows_plan_before_approve(self, mock_console: Console) -> None:
        from caskmcp.ui.flows.gate_review import gate_review_flow

        tools = [_make_tool(risk_tier="low")]
        lockfile = MagicMock()

        result = MagicMock()
        result.approved_ids = ["get_users"]

        with (
            patch("caskmcp.ui.flows.gate_review.err_console", mock_console),
            patch(
                "caskmcp.ui.flows.gate_review.load_lockfile_tools",
                return_value=(lockfile, tools),
            ),
            patch("caskmcp.ui.flows.gate_review.select_one", return_value="approve_all"),
            patch("caskmcp.ui.flows.gate_review.confirm", return_value=True),
            patch(
                "caskmcp.ui.flows.gate_review.run_gate_approve",
                return_value=result,
            ),
        ):
            gate_review_flow(lockfile_path="/some/lockfile.yaml")

        output = mock_console.file.getvalue()  # type: ignore[attr-defined]
        assert "Will run" in output
        assert "cask gate allow" in output


class TestGateSnapshotFlow:
    """gate_snapshot_flow validates and shows plan."""

    def test_no_lockfiles(self, mock_console: Console) -> None:
        from caskmcp.ui.flows.gate_snapshot import gate_snapshot_flow

        with patch("caskmcp.ui.flows.gate_snapshot.err_console", mock_console):
            gate_snapshot_flow(root_path="/nonexistent")

        output = mock_console.file.getvalue()  # type: ignore[attr-defined]
        assert "No lockfiles found" in output

    def test_rejects_directory(self, tmp_path: Path, mock_console: Console) -> None:
        from caskmcp.ui.flows.gate_snapshot import gate_snapshot_flow

        with patch("caskmcp.ui.flows.gate_snapshot.err_console", mock_console):
            gate_snapshot_flow(lockfile_path=str(tmp_path))

        output = mock_console.file.getvalue()  # type: ignore[attr-defined]
        assert "Expected a file, got a directory" in output

    def test_pending_tools_triggers_review_offer(self, mock_console: Console) -> None:
        from caskmcp.ui.flows.gate_snapshot import gate_snapshot_flow

        tools = [_make_tool()]
        lockfile = MagicMock()

        with (
            patch("caskmcp.ui.flows.gate_snapshot.err_console", mock_console),
            patch(
                "caskmcp.ui.flows.gate_snapshot.load_lockfile_tools",
                return_value=(lockfile, tools),
            ),
            # User declines to jump to review
            patch("caskmcp.ui.flows.gate_snapshot.confirm", return_value=False),
            patch("caskmcp.ui.flows.gate_snapshot.run_gate_snapshot") as mock_snap,
        ):
            gate_snapshot_flow(lockfile_path="/some/lockfile.yaml")
            mock_snap.assert_not_called()

        output = mock_console.file.getvalue()  # type: ignore[attr-defined]
        assert "pending approval" in output

    def test_shows_plan_on_ready(self, mock_console: Console) -> None:
        from caskmcp.ui.flows.gate_snapshot import gate_snapshot_flow

        tools = [_make_tool(status=ApprovalStatus.APPROVED)]
        lockfile = MagicMock()

        with (
            patch("caskmcp.ui.flows.gate_snapshot.err_console", mock_console),
            patch(
                "caskmcp.ui.flows.gate_snapshot.load_lockfile_tools",
                return_value=(lockfile, tools),
            ),
            patch("caskmcp.ui.flows.gate_snapshot.confirm", return_value=True),
            patch("caskmcp.ui.flows.gate_snapshot.run_gate_snapshot", return_value="/path/snap"),
        ):
            gate_snapshot_flow(lockfile_path="/some/lockfile.yaml")

        output = mock_console.file.getvalue()  # type: ignore[attr-defined]
        assert "Will run" in output
        assert "cask gate snapshot" in output
        assert "Baseline snapshot created" in output
