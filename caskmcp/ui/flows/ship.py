"""Ship Secure Agent — end-to-end governed agent deployment.

The flagship TUI flow. Guides the user through:
  Capture → Review → Snapshot → Config → Verify → Serve → Monitor

Each stage follows the plan-first pattern (show → confirm → execute → summary).
"""

from __future__ import annotations

from pathlib import Path

from caskmcp.ui.console import err_console
from caskmcp.ui.discovery import find_lockfiles, find_toolpacks
from caskmcp.ui.echo import echo_plan, echo_summary
from caskmcp.ui.prompts import confirm, input_text, select_one

SHIP_STAGES = [
    ("capture", "Capture API surface"),
    ("review", "Review & approve tools"),
    ("snapshot", "Materialize baseline"),
    ("config", "Generate MCP client config"),
    ("verify", "Run verification contracts"),
    ("serve", "Show serve command"),
    ("monitor", "CI integration hints"),
]


def ship_secure_agent_flow(*, root: Path, verbose: bool = False) -> None:
    """End-to-end guided flow to ship a secure governed agent."""
    con = err_console

    con.print()
    con.print("[heading]Ship Secure Agent[/heading]")
    con.print("[muted]Capture, govern, configure, verify, and serve — all in one flow.[/muted]")
    con.print()

    _show_progress(current_stage=0, done_stages=set())

    # Stage 1: Capture
    con.print()
    con.print("[step.active]>> Stage 1: Capture[/step.active]")
    toolpack_path = _stage_capture(root=root, verbose=verbose)
    if toolpack_path is None:
        return
    done = {0}
    _show_progress(current_stage=1, done_stages=done)

    # Stage 2: Review
    con.print()
    con.print("[step.active]>> Stage 2: Review & Approve[/step.active]")
    lockfile_path = _stage_review(root=root, verbose=verbose)
    if lockfile_path is None:
        return
    done.add(1)
    _show_progress(current_stage=2, done_stages=done)

    # Stage 3: Snapshot
    con.print()
    con.print("[step.active]>> Stage 3: Baseline Snapshot[/step.active]")
    if not _stage_snapshot(lockfile_path=lockfile_path, root=root):
        return
    done.add(2)
    _show_progress(current_stage=3, done_stages=done)

    # Stage 4: Config
    con.print()
    con.print("[step.active]>> Stage 4: MCP Client Config[/step.active]")
    _stage_config(toolpack_path=toolpack_path, root=root)
    done.add(3)
    _show_progress(current_stage=4, done_stages=done)

    # Stage 5: Verify
    con.print()
    con.print("[step.active]>> Stage 5: Verification[/step.active]")
    _stage_verify(toolpack_path=toolpack_path, root=root, verbose=verbose)
    done.add(4)
    _show_progress(current_stage=5, done_stages=done)

    # Stage 6: Serve
    con.print()
    con.print("[step.active]>> Stage 6: Serve[/step.active]")
    _stage_serve(toolpack_path=toolpack_path)
    done.add(5)
    _show_progress(current_stage=6, done_stages=done)

    # Stage 7: Monitor
    con.print()
    con.print("[step.active]>> Stage 7: CI Integration[/step.active]")
    _stage_monitor(toolpack_path=toolpack_path, lockfile_path=lockfile_path)
    done.add(6)
    _show_progress(current_stage=7, done_stages=done)

    con.print()
    con.print("[success]Ship Secure Agent complete![/success]")


def _show_progress(current_stage: int, done_stages: set[int]) -> None:
    """Display a compact progress indicator."""
    con = err_console
    parts: list[str] = []
    for i, (_, label) in enumerate(SHIP_STAGES):
        if i in done_stages:
            parts.append(f"[step.done]✓ {label}[/step.done]")
        elif i == current_stage:
            parts.append(f"[step.active]>> {label}[/step.active]")
        else:
            parts.append(f"[step.pending]  {label}[/step.pending]")
    con.print()
    for p in parts:
        con.print(f"  {p}")


def _stage_capture(*, root: Path, verbose: bool) -> str | None:
    """Capture API surface. Returns toolpack_path or None on abort."""
    con = err_console

    # Check for existing toolpacks — offer to skip
    existing = find_toolpacks(root)
    if existing:
        con.print(f"[info]Found {len(existing)} existing toolpack(s).[/info]")
        if confirm("Use an existing toolpack (skip capture)?", default=True, console=con):
            if len(existing) == 1:
                return str(existing[0])
            return select_one(
                [str(p) for p in existing],
                prompt="Select toolpack",
                console=con,
            )

    # Collect capture inputs
    start_url = input_text("API URL to capture", console=con)
    if not start_url:
        con.print("[warning]URL is required.[/warning]")
        return None

    hosts_raw = input_text("API hosts to capture (comma-separated)", console=con)
    if not hosts_raw:
        con.print("[warning]At least one host is required.[/warning]")
        return None
    hosts = [h.strip() for h in hosts_raw.split(",") if h.strip()]

    name = input_text("Session name (optional)", console=con)

    cmd = ["cask", "mint", start_url]
    for h in hosts:
        cmd.extend(["-a", h])
    if name:
        cmd.extend(["-n", name])

    echo_plan([cmd], console=con)

    if not confirm("Proceed with capture?", default=True, console=con):
        return None

    con.print("[info]Starting capture...[/info]")
    try:
        from caskmcp.cli.mint import run_mint

        run_mint(
            start_url=start_url,
            allowed_hosts=tuple(hosts),
            name=name or None,
            scope="first_party_only",
            headless=True,
            script=None,
            duration=30,
            output=str(root),
            deterministic=True,
            runtime="local",
            runtime_build=False,
            runtime_tag=None,
            runtime_version_pin=None,
            print_mcp_config=False,
            verbose=verbose,
            auth_profile=None,
            webmcp=False,
            redaction_profile="default_safe",
        )
    except SystemExit:
        pass
    except Exception as exc:
        con.print(f"[error]Capture failed: {exc}[/error]")
        if confirm("Retry?", default=False, console=con):
            return _stage_capture(root=root, verbose=verbose)
        return None

    echo_summary([cmd], console=con)
    con.print("[success]Capture complete.[/success]")

    # Find the new toolpack
    new_toolpacks = find_toolpacks(root)
    if new_toolpacks:
        return str(new_toolpacks[-1])
    return None


def _stage_review(*, root: Path, verbose: bool) -> str | None:
    """Review and approve tools. Returns lockfile_path or None."""
    con = err_console

    lockfiles = find_lockfiles(root)
    if not lockfiles:
        con.print("[error]No lockfiles found. Capture may have failed.[/error]")
        return None

    lockfile_path = str(lockfiles[0])
    if len(lockfiles) > 1:
        lockfile_path = select_one(
            [str(p) for p in lockfiles],
            prompt="Select lockfile",
            console=con,
        )

    from caskmcp.ui.flows.gate_review import gate_review_flow

    gate_review_flow(lockfile_path=lockfile_path, root_path=str(root), verbose=verbose)
    return lockfile_path


def _stage_snapshot(*, lockfile_path: str, root: Path) -> bool:
    """Create baseline snapshot. Returns True on success."""
    con = err_console

    cmd = ["cask", "gate", "snapshot", "--lockfile", lockfile_path]
    echo_plan([cmd], console=con)

    if not confirm("Create baseline snapshot?", default=True, console=con):
        return False

    try:
        from caskmcp.ui.runner import run_gate_snapshot

        run_gate_snapshot(lockfile_path=lockfile_path, root_path=str(root))
        con.print("[success]Baseline snapshot created.[/success]")
        echo_summary([cmd], console=con)
        return True
    except Exception as exc:
        con.print(f"[error]Snapshot failed: {exc}[/error]")
        con.print("You may need to approve all pending tools first.")
        return False


def _stage_config(*, toolpack_path: str, root: Path) -> None:
    """Generate MCP client config snippet."""
    from caskmcp.ui.flows.config import config_flow

    config_flow(toolpack_path=toolpack_path, root=root)


def _stage_verify(*, toolpack_path: str, root: Path, verbose: bool) -> None:
    """Run verification contracts."""
    con = err_console

    cmd = ["cask", "verify", "--toolpack", toolpack_path]
    echo_plan([cmd], console=con)

    if not confirm("Run verification?", default=True, console=con):
        con.print("[muted]Skipped verification.[/muted]")
        return

    try:
        from caskmcp.cli.verify import run_verify

        run_verify(
            toolpack_path=toolpack_path,
            mode="all",
            verbose=verbose,
            root_path=str(root),
        )
        con.print("[success]Verification passed.[/success]")
    except SystemExit:
        con.print("[warning]Verification had issues. Check output above.[/warning]")
    except Exception as exc:
        con.print(f"[error]Verification failed: {exc}[/error]")

    echo_summary([cmd], console=con)


def _stage_serve(*, toolpack_path: str) -> None:
    """Show the serve command (don't auto-start)."""
    con = err_console

    serve_cmd = f"cask serve --toolpack {toolpack_path}"
    con.print()
    con.print("[heading]To start the governed MCP server:[/heading]")
    con.print(f"  [command]{serve_cmd}[/command]")
    con.print("[muted]This runs in the foreground. Press Ctrl+C to stop.[/muted]")


def _stage_monitor(*, toolpack_path: str, lockfile_path: str) -> None:
    """Print CI integration commands."""
    con = err_console

    con.print()
    con.print("[heading]Add to your CI pipeline:[/heading]")
    con.print(f"  [command]cask gate check --lockfile {lockfile_path}[/command]")
    con.print(f"  [command]cask verify --toolpack {toolpack_path}[/command]")
    con.print(f"  [command]cask drift --toolpack {toolpack_path}[/command]")
    con.print()
    con.print("[muted]These commands exit non-zero on failure, suitable for CI checks.[/muted]")
