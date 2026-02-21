"""Repair flow — diagnosis + suggested fixes + jump-to-gate.

Runs doctor checks, classifies failures, suggests specific fix commands,
and offers to jump to gate review when pending tools are detected.
"""

from __future__ import annotations

from pathlib import Path

from caskmcp.ui.console import err_console
from caskmcp.ui.discovery import find_lockfiles, find_toolpacks
from caskmcp.ui.prompts import confirm, select_one

# ---------------------------------------------------------------------------
# Failure classification → suggested fix commands
# ---------------------------------------------------------------------------

_FIX_MAP: list[tuple[str, str, list[str]]] = [
    # (check_name_substring, detail_substring, fix_commands)
    ("tools.json", "missing", ["cask mint <url> -a <host>  # re-capture API surface"]),
    ("toolsets.yaml", "missing", ["cask gate sync --toolpack <path>"]),
    ("policy.yaml", "missing", ["cask gate sync --toolpack <path>"]),
    ("baseline.json", "missing", ["cask gate snapshot --lockfile <path>"]),
    ("lockfile", "missing", ["cask gate sync --toolpack <path>"]),
    ("artifacts digest", "mismatch", ["cask gate sync --toolpack <path>"]),
    ("evidence hash", "mismatch", ["cask verify --toolpack <path>"]),
    ("mcp dependency", "not installed", ['pip install "caskmcp[mcp]"']),
    ("docker", "not available", ["Install Docker, or re-run with --runtime local"]),
    ("container:", "missing", ["cask mint <url> --runtime container --runtime-build"]),
]


def _suggest_fixes(name: str, detail: str) -> list[str]:
    """Return suggested fix commands for a failed check."""
    fixes: list[str] = []
    for check_sub, detail_sub, cmds in _FIX_MAP:
        if check_sub in name and detail_sub in detail.lower():
            fixes.extend(cmds)
    if not fixes:
        # Fallback: echo the raw detail which often contains a hint
        fixes.append(detail)
    return fixes


def _has_pending_tools(toolpack_path: str) -> bool:
    """Check if the toolpack has any pending lockfile with unapproved tools."""
    try:
        from caskmcp.ui.runner import load_lockfile_tools

        tp_dir = Path(toolpack_path).parent
        lockfiles = list(tp_dir.glob("*.pending.*"))
        for lf in lockfiles:
            _, tools = load_lockfile_tools(str(lf))
            from caskmcp.core.approval.lockfile import ApprovalStatus

            if any(t.status == ApprovalStatus.PENDING for t in tools):
                return True
    except Exception:
        pass
    return False


def repair_flow(
    *,
    toolpack_path: str | None = None,
    root: Path = Path(".caskmcp"),
    verbose: bool = False,
) -> None:
    """Interactive repair flow: diagnose, suggest fixes, offer gate review."""
    con = err_console

    con.print()
    con.print("[heading]Repair — Diagnose & Fix[/heading]")
    con.print()

    # Resolve toolpack
    if toolpack_path is None:
        candidates = find_toolpacks(root)
        if not candidates:
            con.print("[error]No toolpacks found. Run cask mint to capture an API first.[/error]")
            return
        if len(candidates) == 1:
            toolpack_path = str(candidates[0])
        else:
            toolpack_path = select_one(
                [str(p) for p in candidates],
                prompt="Select toolpack to diagnose",
                console=con,
            )

    # Run doctor
    if not confirm("Run doctor checks?", default=True, console=con):
        return

    from caskmcp.ui.runner import run_doctor_checks

    result = run_doctor_checks(toolpack_path)

    # Display results
    failures = [c for c in result.checks if not c.passed]

    if not failures:
        con.print("[success]All checks passed — toolpack is healthy.[/success]")
    else:
        con.print(f"[warning]{len(failures)} issue(s) found:[/warning]")
        con.print()

        for check in failures:
            con.print(f"  [error]✗ {check.name}[/error]: {check.detail}")
            fixes = _suggest_fixes(check.name, check.detail)
            for fix in fixes:
                con.print(f"    [command]{fix}[/command]")
            con.print()

    # Check for pending tools
    if _has_pending_tools(toolpack_path):
        con.print("[info]Pending tools detected — tools need approval.[/info]")
        if confirm("Jump to gate review?", default=True, console=con):
            from caskmcp.ui.flows.gate_review import gate_review_flow

            lockfiles = find_lockfiles(root)
            lf = str(lockfiles[0]) if lockfiles else None
            gate_review_flow(
                lockfile_path=lf,
                root_path=str(root),
                verbose=verbose,
            )
