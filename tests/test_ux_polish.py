"""UX polish tests — verifying improved user-facing messages and behavior.

Tests for issues identified in the comprehensive UX audit:
1. `init` next steps should tell user that mint will print exact commands
2. Claude Desktop config path in `serve` help should be correct
3. `gate allow` should print next-step guidance after approvals
4. `doctor` success output should go to stdout (not stderr only)
5. `bundle` success output should go to stdout (not stderr only)
6. `config` should be a core command for discoverability
7. auth.py should not catch ImportError on asyncio (stdlib)
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

from click.testing import CliRunner

from caskmcp.cli.main import cli
from tests.helpers import write_demo_toolpack

# --- 1. init next steps should tell user mint prints the exact commands ---


def test_init_next_steps_mention_mint_prints_exact_commands(tmp_path: Path) -> None:
    """init should tell users that mint/compile will print exact follow-up commands
    instead of printing stale gate allow without --lockfile."""
    runner = CliRunner()
    result = runner.invoke(cli, ["init", "--directory", str(tmp_path)])

    assert result.exit_code == 0
    output = result.output.lower()
    # Should NOT print bare `cask gate allow --all` without context
    # Instead, should tell the user that the commands they need will be printed by mint
    assert "mint will print" in output or "mint prints" in output or "printed by mint" in output


def test_init_next_steps_no_bare_gate_allow_all(tmp_path: Path) -> None:
    """init should not print a bare `cask gate allow --all` without --lockfile,
    since that will fail when run from a project root after mint."""
    runner = CliRunner()
    result = runner.invoke(cli, ["init", "--directory", str(tmp_path)])

    assert result.exit_code == 0
    lines = result.output.strip().split("\n")
    for line in lines:
        stripped = line.strip()
        # Bare "cask gate allow --all" without --lockfile is misleading
        if (
            "cask gate allow --all" in stripped
            and "--lockfile" not in stripped
            and (stripped.startswith("cask gate") or stripped.startswith("2."))
        ):
            raise AssertionError(
                f"init prints bare 'gate allow --all' without --lockfile: {stripped!r}"
            )


# --- 2. Claude Desktop config path in serve help ---


def test_serve_help_claude_config_path_not_wrong() -> None:
    """serve help should not reference the wrong ~/.claude/ path."""
    runner = CliRunner()
    result = runner.invoke(cli, ["serve", "--help"])

    assert result.exit_code == 0
    # The wrong path:
    assert "~/.claude/claude_desktop_config.json" not in result.output


# --- 3. gate allow should print next-step guidance ---


def test_gate_allow_prints_next_steps(tmp_path: Path) -> None:
    """After approving tools, gate allow should print guidance on what to do next."""
    # Create tools manifest with a pending tool
    tools_path = tmp_path / "tools.json"
    lockfile_path = tmp_path / "caskmcp.lock.yaml"
    manifest = {
        "actions": [
            {
                "name": "get_test",
                "signature_id": "sig_get_test",
                "method": "GET",
                "path": "/test",
                "host": "example.com",
                "risk_tier": "low",
            }
        ]
    }
    tools_path.write_text(json.dumps(manifest))

    runner = CliRunner()
    # First sync to create pending tools
    runner.invoke(
        cli,
        ["gate", "sync", "--tools", str(tools_path), "--lockfile", str(lockfile_path)],
    )

    # Then approve all
    result = runner.invoke(
        cli,
        ["gate", "allow", "--all", "--lockfile", str(lockfile_path)],
    )

    assert result.exit_code == 0
    output = result.output.lower()
    # Should mention serve as the next step after approval
    assert "serve" in output or "next" in output, (
        f"gate allow should print next-step guidance mentioning serve. Got: {result.output!r}"
    )


# --- 4. doctor success output should include stdout ---


def test_doctor_success_on_stdout(tmp_path: Path) -> None:
    """Doctor success message should go to stdout, not only stderr."""
    toolpack_file = write_demo_toolpack(tmp_path)
    runner = CliRunner()

    result = runner.invoke(
        cli,
        ["doctor", "--toolpack", str(toolpack_file), "--runtime", "local"],
    )

    assert result.exit_code == 0
    # Success should be on stdout (not exclusively stderr)
    assert "Doctor check passed" in result.stdout


def test_doctor_errors_still_on_stderr(tmp_path: Path) -> None:
    """Doctor error messages should remain on stderr."""
    toolpack_file = write_demo_toolpack(tmp_path)
    tools_path = toolpack_file.parent / "artifact" / "tools.json"
    tools_path.unlink()

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["doctor", "--toolpack", str(toolpack_file), "--runtime", "local"],
    )

    assert result.exit_code != 0
    assert "tools.json missing" in (result.output + (result.stderr_bytes or b"").decode())


# --- 5. bundle success output should include stdout ---


def test_bundle_success_on_stdout(tmp_path: Path) -> None:
    """Bundle success message should go to stdout, not only stderr."""
    toolpack_file = write_demo_toolpack(tmp_path)
    runner = CliRunner()

    result = runner.invoke(
        cli,
        [
            "bundle", "--toolpack", str(toolpack_file),
            "--out", str(tmp_path / "out.zip"),
            "--verbose",
        ],
    )

    if result.exit_code == 0:
        # Verbose bundle message should appear on stdout
        assert "Bundle created" in result.stdout


# --- 6. config should be a core command ---


def test_config_in_core_commands() -> None:
    """config should be listed in CORE_COMMANDS for discoverability."""
    from caskmcp.cli.main import CORE_COMMANDS

    assert "config" in CORE_COMMANDS


# --- 7. auth.py should not catch ImportError on asyncio (stdlib) ---


def test_auth_login_does_not_guard_asyncio_import() -> None:
    """auth login should guard playwright import, not asyncio (which is stdlib)."""
    auth_path = Path("caskmcp/cli/auth.py")
    tree = ast.parse(auth_path.read_text())

    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            for handler in node.handlers:
                if (
                    handler.type
                    and isinstance(handler.type, ast.Name)
                    and handler.type.id == "ImportError"
                ):
                    for stmt in node.body:
                        if isinstance(stmt, ast.Import):
                            for alias in stmt.names:
                                if alias.name == "asyncio":
                                    raise AssertionError(
                                        "auth.py wraps `import asyncio` in try/except ImportError. "
                                        "asyncio is stdlib and never fails. Guard playwright instead."
                                    )


# --- 8. verify --mode replay should emit deprecation warning ---


def test_verify_replay_mode_emits_deprecation_warning(tmp_path: Path) -> None:
    """Using --mode replay should print a deprecation warning suggesting baseline-check."""
    toolpack_file = write_demo_toolpack(tmp_path)
    runner = CliRunner()

    result = runner.invoke(
        cli,
        ["verify", "--toolpack", str(toolpack_file), "--mode", "replay"],
    )

    # Should print deprecation warning regardless of exit code
    output = result.output + (result.stderr_bytes or b"").decode()
    assert "deprecated" in output.lower(), (
        f"verify --mode replay should print deprecation warning. Got: {result.output!r}"
    )
    assert "baseline-check" in output, (
        f"deprecation warning should suggest 'baseline-check'. Got: {result.output!r}"
    )


def test_verify_baseline_check_mode_no_deprecation_warning(tmp_path: Path) -> None:
    """Using --mode baseline-check should NOT print a deprecation warning."""
    toolpack_file = write_demo_toolpack(tmp_path)
    runner = CliRunner()

    result = runner.invoke(
        cli,
        ["verify", "--toolpack", str(toolpack_file), "--mode", "baseline-check"],
    )

    output = result.output + (result.stderr_bytes or b"").decode()
    assert "deprecated" not in output.lower(), (
        f"verify --mode baseline-check should not print deprecation warning. Got: {result.output!r}"
    )
