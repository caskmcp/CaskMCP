"""CLI tests for capture record Playwright dependency/error handling."""

from __future__ import annotations

from datetime import UTC, datetime

from click.testing import CliRunner

from caskmcp.cli.main import cli
from caskmcp.models.capture import CaptureSession, CaptureSource, HttpExchange, HTTPMethod


def _session_with_exchange() -> CaptureSession:
    return CaptureSession(
        id="cap_demo",
        name="Demo",
        source=CaptureSource.PLAYWRIGHT,
        created_at=datetime(2026, 2, 6, tzinfo=UTC),
        allowed_hosts=["api.example.com"],
        exchanges=[
            HttpExchange(
                url="https://api.example.com/users",
                method=HTTPMethod.GET,
                host="api.example.com",
                path="/users",
                response_status=200,
            )
        ],
    )


def test_capture_record_missing_playwright_exact_error(monkeypatch) -> None:
    runner = CliRunner()

    async def _raise_import_error(self, *args, **kwargs):  # noqa: ARG001, ANN001
        raise ImportError("No module named 'playwright'")

    monkeypatch.setattr(
        "caskmcp.core.capture.playwright_capture.PlaywrightCapture.capture",
        _raise_import_error,
    )

    result = runner.invoke(
        cli,
        [
            "capture",
            "record",
            "https://app.example.com",
            "-a",
            "api.example.com",
        ],
    )

    assert result.exit_code != 0
    assert result.stdout == ""
    assert (
        result.stderr
        == 'Error: Playwright not installed. Install with: pip install "caskmcp[playwright]"\n'
    )


def test_capture_record_missing_browsers_exact_error(monkeypatch) -> None:
    runner = CliRunner()

    async def _raise_missing_browser(self, *args, **kwargs):  # noqa: ARG001, ANN001
        raise RuntimeError(
            "BrowserType.launch: Executable doesn't exist at /tmp/chromium "
            "Please run: playwright install chromium"
        )

    monkeypatch.setattr(
        "caskmcp.core.capture.playwright_capture.PlaywrightCapture.capture",
        _raise_missing_browser,
    )

    result = runner.invoke(
        cli,
        [
            "capture",
            "record",
            "https://app.example.com",
            "-a",
            "api.example.com",
        ],
    )

    assert result.exit_code != 0
    assert result.stdout == ""
    assert (
        result.stderr
        == "Error: Playwright browsers not installed. Run: playwright install chromium\n"
    )


def test_capture_record_missing_browsers_verbose_still_single_line(monkeypatch) -> None:
    runner = CliRunner()

    async def _raise_missing_browser(self, *args, **kwargs):  # noqa: ARG001, ANN001
        raise RuntimeError("Executable doesn't exist; run playwright install chromium")

    monkeypatch.setattr(
        "caskmcp.core.capture.playwright_capture.PlaywrightCapture.capture",
        _raise_missing_browser,
    )

    result = runner.invoke(
        cli,
        [
            "-v",
            "capture",
            "record",
            "https://app.example.com",
            "-a",
            "api.example.com",
        ],
    )

    assert result.exit_code != 0
    assert "Traceback" not in result.stderr
    assert (
        result.stderr
        == "Error: Playwright browsers not installed. Run: playwright install chromium\n"
    )


def test_capture_record_unexpected_error_verbose_shows_traceback(monkeypatch) -> None:
    runner = CliRunner()

    async def _raise_unexpected(self, *args, **kwargs):  # noqa: ARG001, ANN001
        raise RuntimeError("boom")

    monkeypatch.setattr(
        "caskmcp.core.capture.playwright_capture.PlaywrightCapture.capture",
        _raise_unexpected,
    )

    result = runner.invoke(
        cli,
        [
            "-v",
            "capture",
            "record",
            "https://app.example.com",
            "-a",
            "api.example.com",
        ],
    )

    assert result.exit_code != 0
    assert "Error during capture: boom" in result.stderr
    assert "Traceback (most recent call last):" in result.stderr


def test_capture_record_success_unchanged(monkeypatch) -> None:
    runner = CliRunner()

    async def _capture(self, *args, **kwargs):  # noqa: ARG001, ANN001
        return _session_with_exchange()

    monkeypatch.setattr(
        "caskmcp.core.capture.playwright_capture.PlaywrightCapture.capture",
        _capture,
    )

    result = runner.invoke(
        cli,
        [
            "capture",
            "record",
            "https://app.example.com",
            "-a",
            "api.example.com",
        ],
    )

    assert result.exit_code == 0
    assert "Capture saved: cap_demo" in result.stdout
    assert result.stderr == ""
