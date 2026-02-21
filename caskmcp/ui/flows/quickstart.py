"""Wizard menu and quickstart flow.

Launched when ``cask`` is invoked with no arguments in an interactive terminal.
"""

from __future__ import annotations

from pathlib import Path

from caskmcp.ui.console import err_console
from caskmcp.ui.discovery import find_lockfiles, find_toolpacks
from caskmcp.ui.prompts import select_one

WIZARD_MENU = [
    ("quickstart", "Quick Start \u2014 capture & govern an API in minutes"),
    ("ship", "Ship Secure Agent \u2014 end-to-end governed agent deployment"),
    ("gate", "Review & approve pending tools"),
    ("config", "Generate MCP client config"),
    ("doctor", "Check toolpack health"),
    ("init", "Initialize Cask in this project"),
    ("exit", "Exit"),
]


def wizard_flow(*, root: Path, verbose: bool = False) -> None:
    """Main wizard entry point."""
    from caskmcp import __version__
    from caskmcp.branding import PRODUCT_NAME

    con = err_console

    # Compact branding banner
    con.print()
    con.print(f"[heading]{PRODUCT_NAME}[/heading] [muted]v{__version__}[/muted]")
    con.print("[muted]Turn any web API into a governed, agent-ready MCP server.[/muted]")

    # Status summary
    toolpacks = find_toolpacks(root)
    lockfiles = find_lockfiles(root)
    pending_count = _count_pending(lockfiles)
    parts = [f"{len(toolpacks)} toolpacks"]
    if pending_count:
        parts.append(f"[warning]{pending_count} pending approvals[/warning]")
    con.print(" | ".join(parts))

    while True:
        choice = select_one(
            [key for key, _ in WIZARD_MENU],
            labels=[label for _, label in WIZARD_MENU],
            prompt="What would you like to do?",
            console=con,
        )

        if choice == "exit":
            return

        _dispatch(choice, root=root, verbose=verbose)

        # After flow, default to exit
        from caskmcp.ui.prompts import confirm

        if not confirm("Return to menu?", default=False, console=con):
            return


def _dispatch(choice: str, *, root: Path, verbose: bool) -> None:
    """Dispatch to the corresponding flow."""
    con = err_console

    if choice == "quickstart":
        _quickstart_flow(root=root, verbose=verbose)
    elif choice == "ship":
        from caskmcp.ui.flows.ship import ship_secure_agent_flow

        ship_secure_agent_flow(root=root, verbose=verbose)
    elif choice == "gate":
        from caskmcp.ui.flows.gate_review import gate_review_flow

        gate_review_flow(root_path=str(root), verbose=verbose)
    elif choice == "config":
        from caskmcp.ui.flows.config import config_flow

        config_flow(root=root)
    elif choice == "doctor":
        from caskmcp.ui.flows.doctor import doctor_flow

        doctor_flow(root=root, verbose=verbose)
    elif choice == "init":
        from caskmcp.ui.flows.init import init_flow

        init_flow(verbose=verbose)
    else:
        con.print(f"[warning]Unknown option: {choice}[/warning]")


def _quickstart_flow(*, root: Path, verbose: bool) -> None:
    """Guided quickstart: capture, approve, configure."""
    from caskmcp.ui.echo import echo_plan
    from caskmcp.ui.prompts import confirm, input_text

    con = err_console

    con.print()
    con.print("[heading]Quick Start[/heading]")
    con.print("Capture an API, approve its tools, and connect an MCP client.\n")

    start_url = input_text("API URL to capture", console=con)
    if not start_url:
        con.print("[warning]URL is required[/warning]")
        return

    hosts_raw = input_text("API hosts to capture (comma-separated)", console=con)
    if not hosts_raw:
        con.print("[warning]At least one host is required[/warning]")
        return
    hosts = [h.strip() for h in hosts_raw.split(",") if h.strip()]

    name = input_text("Session name (optional)", console=con)

    # Build mint command
    cmd = ["cask", "mint", start_url]
    for h in hosts:
        cmd.extend(["-a", h])
    if name:
        cmd.extend(["-n", name])

    echo_plan([cmd], console=con)

    if not confirm("Proceed with capture?", default=True, console=con):
        return

    # Execute mint
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
        return

    con.print("[success]Capture complete.[/success]")
    con.print("Next: review and approve tools with 'cask gate allow'")


def _count_pending(lockfiles: list[Path]) -> int:
    """Count total pending tools across all lockfiles."""
    count = 0
    for lf in lockfiles:
        try:
            from caskmcp.core.approval import LockfileManager

            mgr = LockfileManager(lf)
            mgr.load()
            count += len(mgr.get_pending())
        except Exception:
            pass
    return count
