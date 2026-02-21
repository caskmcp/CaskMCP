"""Interactive doctor flow."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from caskmcp.ui.console import err_console
from caskmcp.ui.discovery import find_toolpacks
from caskmcp.ui.echo import echo_plan, echo_summary
from caskmcp.ui.prompts import confirm, select_one
from caskmcp.ui.runner import run_doctor_checks
from caskmcp.ui.tables import doctor_checklist


def doctor_flow(
    *,
    toolpack_path: str | None = None,
    root: Path | None = None,
    verbose: bool = False,  # noqa: ARG001
    ctx: Any = None,  # noqa: ARG001
    missing_param: str | None = None,  # noqa: ARG001
) -> None:
    """Interactive doctor flow.

    If toolpack_path is None, prompts user to select a toolpack.
    Shows plan, confirms, runs checks, displays Rich checklist.
    """
    con = err_console

    if root is None:
        root = Path(".caskmcp")

    # Resolve toolpack path
    if toolpack_path is None:
        candidates = find_toolpacks(root)
        if not candidates:
            con.print("[error]No toolpacks found.[/error]")
            con.print("Run 'cask mint' or 'cask capture import' first.")
            return
        if len(candidates) == 1:
            toolpack_path = str(candidates[0])
            con.print(f"Found toolpack: [bold]{toolpack_path}[/bold]")
        else:
            labels = [str(p) for p in candidates]
            toolpack_path = select_one(
                labels,
                prompt="Select toolpack",
                console=con,
            )

    # Plan
    cmd = ["cask", "doctor", "--toolpack", toolpack_path]
    echo_plan([cmd], console=con)

    if not confirm("Run doctor checks?", default=True, console=con):
        return

    # Execute
    try:
        result = run_doctor_checks(toolpack_path, runtime="auto")
    except (FileNotFoundError, ValueError) as exc:
        con.print(f"[error]Error: {exc}[/error]")
        return

    # Display
    check_tuples = [(c.name, c.passed, c.detail) for c in result.checks]
    table = doctor_checklist(check_tuples)
    con.print()
    con.print(table)
    con.print()

    if result.all_passed:
        con.print("[success]All checks passed.[/success]")
        con.print(f"Next: cask serve --toolpack {toolpack_path}")
    else:
        con.print("[error]Some checks failed. Fix the errors above and re-run.[/error]")

    echo_summary([cmd], console=con)
