"""Repair flow — doctor checks + RepairEngine diagnosis + suggested fixes.

Two-phase interactive flow:
  Phase 1: Quick doctor health checks (existing infrastructure)
  Phase 2: Deep RepairEngine diagnosis from audit logs, drift, and verify reports

Conforms to the InteractiveFlow protocol for dispatch on MissingParameter.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from caskmcp.ui.console import err_console
from caskmcp.ui.discovery import find_lockfiles, find_toolpacks
from caskmcp.ui.echo import echo_plan, echo_summary
from caskmcp.ui.prompts import confirm, select_one
from caskmcp.ui.tables import doctor_checklist

# ---------------------------------------------------------------------------
# Failure classification -> suggested fix commands (doctor Phase 1)
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

_SEVERITY_STYLES: dict[str, str] = {
    "critical": "error",
    "error": "error",
    "warning": "warning",
    "info": "muted",
}

_KIND_LABELS: dict[str, str] = {
    "safe": "[success]safe[/success]",
    "approval_required": "[warning]approval required[/warning]",
    "manual": "[error]manual[/error]",
}


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


# ---------------------------------------------------------------------------
# RepairEngine integration (Phase 2)
# ---------------------------------------------------------------------------


def _run_engine_diagnosis(
    toolpack_path: str,
    con: Any,
) -> None:
    """Run RepairEngine with auto-discover and display structured results."""
    try:
        from caskmcp.core.repair.engine import RepairEngine
        from caskmcp.core.toolpack import load_toolpack, resolve_toolpack_paths

        tp_path = Path(toolpack_path)
        toolpack = load_toolpack(tp_path)
        resolved = resolve_toolpack_paths(toolpack=toolpack, toolpack_path=tp_path)
    except Exception as exc:
        con.print(f"[warning]Could not load toolpack for deep diagnosis: {exc}[/warning]")
        return

    try:
        engine = RepairEngine(
            toolpack=toolpack,
            toolpack_path=Path(toolpack_path),
            resolved=resolved,
        )
        report = engine.run(context_paths=[], auto_discover=True)
    except Exception as exc:
        con.print(f"[warning]Engine diagnosis failed: {exc}[/warning]")
        return

    # No issues found
    if report.diagnosis.total_issues == 0:
        con.print("[success]No issues found in audit logs, drift reports, or verify reports.[/success]")
    else:
        # Display diagnosis items
        con.print(f"[heading]Deep Diagnosis: {report.diagnosis.total_issues} issue(s)[/heading]")
        con.print()

        for item in report.diagnosis.items:
            sev_style = _SEVERITY_STYLES.get(item.severity, "")
            if sev_style:
                con.print(f"  [{sev_style}]{item.severity.upper()}[/{sev_style}]  {item.title}")
            else:
                con.print(f"  {item.severity.upper()}  {item.title}")
            con.print(f"    {item.description}")
            con.print()

        # Display patch plan
        plan = report.patch_plan
        if plan.total_patches > 0:
            con.print("[heading]Recommended Actions[/heading]")
            con.print()

            for patch in plan.patches:
                kind_label = _KIND_LABELS.get(patch.kind, patch.kind)
                con.print(f"  {kind_label}  {patch.title}")
                con.print(f"    {patch.description}")
                if patch.risk_note:
                    con.print(f"    [muted]Risk: {patch.risk_note}[/muted]")
                con.print(f"    [command]{patch.cli_command}[/command]")
                con.print()

            # Summary counts
            parts: list[str] = []
            if plan.safe_count:
                parts.append(f"[success]{plan.safe_count} safe[/success]")
            if plan.approval_required_count:
                parts.append(f"[warning]{plan.approval_required_count} need approval[/warning]")
            if plan.manual_count:
                parts.append(f"[error]{plan.manual_count} manual[/error]")
            if parts:
                con.print("  Summary: " + "  ".join(parts))
                con.print()

        # Verify snapshot
        if report.verify_before and report.verify_before.verify_status:
            status = report.verify_before.verify_status
            if status == "fail":
                con.print("[error]Verify (contracts): FAIL[/error]")
            elif status == "pass":
                con.print("[success]Verify (contracts): PASS[/success]")
            else:
                con.print(f"[muted]Verify (contracts): {status}[/muted]")

    # Context files used
    if report.diagnosis.context_files_used:
        con.print()
        con.print("[muted]Context files analyzed:[/muted]")
        for f in report.diagnosis.context_files_used:
            con.print(f"  [muted]{f}[/muted]")


# ---------------------------------------------------------------------------
# Main flow entry point
# ---------------------------------------------------------------------------


def repair_flow(
    *,
    toolpack_path: str | None = None,
    root: Path | None = None,
    verbose: bool = False,
    ctx: Any = None,  # noqa: ARG001
    missing_param: str | None = None,  # noqa: ARG001
) -> None:
    """Interactive repair flow: diagnose, suggest fixes, offer gate review.

    Phase 1: Quick doctor health checks
    Phase 2: Deep RepairEngine diagnosis from context files
    """
    con = err_console

    if root is None:
        root = Path(".caskmcp")

    con.print()
    con.print("[heading]Repair -- Diagnose & Fix[/heading]")
    con.print()

    # Resolve toolpack
    if toolpack_path is None:
        candidates = find_toolpacks(root)
        if not candidates:
            con.print("[error]No toolpacks found. Run cask mint to capture an API first.[/error]")
            return
        if len(candidates) == 1:
            toolpack_path = str(candidates[0])
            con.print(f"Found toolpack: [bold]{toolpack_path}[/bold]")
        else:
            toolpack_path = select_one(
                [str(p) for p in candidates],
                prompt="Select toolpack to diagnose",
                console=con,
            )

    # -----------------------------------------------------------------------
    # Phase 1: Doctor health checks
    # -----------------------------------------------------------------------

    cmd = ["cask", "repair", "--toolpack", toolpack_path]
    echo_plan([cmd], console=con)

    if not confirm("Run doctor checks?", default=True, console=con):
        return

    from caskmcp.ui.runner import run_doctor_checks

    try:
        result = run_doctor_checks(toolpack_path)
    except (FileNotFoundError, ValueError) as exc:
        con.print(f"[error]Error running doctor checks: {exc}[/error]")
        return

    # Display doctor results as checklist table
    check_tuples = [(c.name, c.passed, c.detail) for c in result.checks]
    table = doctor_checklist(check_tuples)
    con.print()
    con.print(table)
    con.print()

    failures = [c for c in result.checks if not c.passed]

    if not failures:
        con.print("[success]All checks passed -- toolpack is healthy.[/success]")
    else:
        con.print(f"[warning]{len(failures)} issue(s) found:[/warning]")
        con.print()

        for check in failures:
            con.print(f"  [error]{check.name}[/error]: {check.detail}")
            fixes = _suggest_fixes(check.name, check.detail)
            for fix in fixes:
                con.print(f"    [command]{fix}[/command]")
            con.print()

    # -----------------------------------------------------------------------
    # Phase 2: Deep RepairEngine diagnosis
    # -----------------------------------------------------------------------

    con.print()
    if confirm("Run deep diagnosis (audit logs, drift, verify)?", default=True, console=con):
        _run_engine_diagnosis(toolpack_path, con)

    # -----------------------------------------------------------------------
    # Check for pending tools -> offer gate review
    # -----------------------------------------------------------------------

    if _has_pending_tools(toolpack_path):
        con.print("[info]Pending tools detected -- tools need approval.[/info]")
        if confirm("Jump to gate review?", default=True, console=con):
            from caskmcp.ui.flows.gate_review import gate_review_flow

            lockfiles = find_lockfiles(root)
            lf = str(lockfiles[0]) if lockfiles else None
            gate_review_flow(
                lockfile_path=lf,
                root_path=str(root),
                verbose=verbose,
            )

    echo_summary([cmd], console=con)
