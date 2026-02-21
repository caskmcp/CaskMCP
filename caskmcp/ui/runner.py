"""Core logic adapter for TUI flows.

Functions here call domain logic directly — no Click context, no stdout/stderr
side effects.  This keeps the TUI layer testable and separable from the CLI.

Functions are added incrementally as flows need them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from caskmcp.core.approval import LockfileManager
from caskmcp.core.approval.lockfile import ApprovalStatus, Lockfile, ToolApproval
from caskmcp.core.approval.signing import resolve_approver
from caskmcp.core.approval.snapshot import materialize_snapshot
from caskmcp.core.toolpack import load_toolpack, resolve_toolpack_paths
from caskmcp.utils.deps import has_mcp_dependency
from caskmcp.utils.runtime import docker_available

# ---------------------------------------------------------------------------
# Doctor
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DoctorCheck:
    """A single doctor check result."""

    name: str
    passed: bool
    detail: str


@dataclass(frozen=True)
class DoctorResult:
    """Aggregate doctor results."""

    checks: list[DoctorCheck]
    runtime_mode: str

    @property
    def all_passed(self) -> bool:
        return all(c.passed for c in self.checks)


def run_doctor_checks(
    toolpack_path: str,
    runtime: str = "auto",
    require_local_mcp: bool = False,
) -> DoctorResult:
    """Run doctor checks and return structured results.

    Raises FileNotFoundError / ValueError if toolpack cannot be loaded.
    """
    from caskmcp.core.approval import compute_artifacts_digest_from_paths

    checks: list[DoctorCheck] = []

    toolpack = load_toolpack(Path(toolpack_path))
    resolved = resolve_toolpack_paths(toolpack=toolpack, toolpack_path=toolpack_path)
    toolpack_root = Path(toolpack_path).resolve().parent

    # Artifact existence checks
    for label, path in [
        ("tools.json", resolved.tools_path),
        ("toolsets.yaml", resolved.toolsets_path),
        ("policy.yaml", resolved.policy_path),
        ("baseline.json", resolved.baseline_path),
    ]:
        exists = path.exists()
        checks.append(DoctorCheck(
            name=label,
            passed=exists,
            detail=str(path) if exists else f"{label} missing: {path}",
        ))

    # Lockfile
    lockfile_path = resolved.approved_lockfile_path or resolved.pending_lockfile_path
    if lockfile_path is None or not lockfile_path.exists():
        checks.append(DoctorCheck(
            name="lockfile",
            passed=False,
            detail="missing; run cask gate sync",
        ))
    else:
        checks.append(DoctorCheck(
            name="lockfile",
            passed=True,
            detail=str(lockfile_path),
        ))

        # Artifacts digest
        if all(c.passed for c in checks[:4]):
            manager = LockfileManager(lockfile_path)
            lockfile = manager.load()
            digest = compute_artifacts_digest_from_paths(
                tools_path=resolved.tools_path,
                toolsets_path=resolved.toolsets_path,
                policy_path=resolved.policy_path,
            )
            digest_match = not lockfile.artifacts_digest or lockfile.artifacts_digest == digest
            checks.append(DoctorCheck(
                name="artifacts digest",
                passed=digest_match,
                detail="matches" if digest_match else "lockfile artifacts digest mismatch; re-run cask gate sync",
            ))

            # Evidence hash
            expected = lockfile.evidence_summary_sha256
            if expected:
                actual = None
                if (
                    resolved.evidence_summary_sha256_path
                    and resolved.evidence_summary_sha256_path.exists()
                ):
                    actual = resolved.evidence_summary_sha256_path.read_text().strip()
                evidence_ok = actual == expected
                checks.append(DoctorCheck(
                    name="evidence hash",
                    passed=evidence_ok,
                    detail="matches" if evidence_ok else "evidence summary hash mismatch; re-run verification",
                ))

    # Runtime checks
    mode = runtime
    if mode == "auto":
        mode = toolpack.runtime.mode if toolpack.runtime else "local"

    if mode == "local":
        if require_local_mcp:
            has_mcp = has_mcp_dependency()
            checks.append(DoctorCheck(
                name="mcp dependency",
                passed=has_mcp,
                detail="installed" if has_mcp else 'mcp not installed. Install with: pip install "caskmcp[mcp]"',
            ))
    elif mode == "container":
        if toolpack.runtime is None or toolpack.runtime.container is None:
            checks.append(DoctorCheck(
                name="container config",
                passed=False,
                detail="runtime container configuration missing in toolpack",
            ))
        else:
            container = toolpack.runtime.container
            for label, rel in [
                ("Dockerfile", container.dockerfile),
                ("entrypoint", container.entrypoint),
                ("run wrapper", container.run),
                ("requirements", container.requirements),
            ]:
                p = toolpack_root / rel
                checks.append(DoctorCheck(
                    name=f"container:{label}",
                    passed=p.exists(),
                    detail=str(p) if p.exists() else f"container runtime file missing: {p}",
                ))
        docker_ok = docker_available()
        checks.append(DoctorCheck(
            name="docker",
            passed=docker_ok,
            detail="available" if docker_ok else "docker not available; install Docker or use --runtime local",
        ))
    else:
        checks.append(DoctorCheck(
            name="runtime mode",
            passed=False,
            detail=f"unknown runtime mode: {mode}",
        ))

    return DoctorResult(checks=checks, runtime_mode=mode)


# ---------------------------------------------------------------------------
# Gate approve / reject / snapshot
# ---------------------------------------------------------------------------


@dataclass
class ApproveResult:
    """Result of an approval operation."""

    approved_ids: list[str] = field(default_factory=list)
    lockfile_path: str = ""
    promoted: bool = False


def run_gate_approve(
    tool_ids: list[str],
    lockfile_path: str,
    *,
    all_pending: bool = False,
    toolset: str | None = None,
    approved_by: str | None = None,
    reason: str | None = None,
    root_path: str = ".caskmcp",
) -> ApproveResult:
    """Approve tools in a lockfile. Returns structured result.

    Raises FileNotFoundError if lockfile missing, ValueError on bad args.
    """
    manager = LockfileManager(lockfile_path)
    if not manager.exists():
        raise FileNotFoundError(f"No lockfile found at: {manager.lockfile_path}")

    manager.load()
    actor = resolve_approver(approved_by)

    if all_pending:
        ids_to_approve = [t.tool_id for t in manager.get_pending()]
    elif toolset:
        ids_to_approve = [
            t.tool_id
            for t in manager.get_pending()
            if toolset in t.toolsets
        ]
    else:
        ids_to_approve = list(tool_ids)

    approved: list[str] = []
    for tid in ids_to_approve:
        tool = manager.get_tool(tid)
        if tool and tool.status == ApprovalStatus.PENDING:
            manager.approve(
                tool_id=tid,
                approved_by=actor,
                reason=reason,
            )
            approved.append(tid)

    manager.save()

    # Check if we should promote + snapshot
    promoted = False
    if not manager.get_pending():
        promoted = _try_promote(manager, root_path)

    return ApproveResult(
        approved_ids=approved,
        lockfile_path=str(manager.lockfile_path),
        promoted=promoted,
    )


def run_gate_reject(
    tool_ids: list[str],
    lockfile_path: str,
    *,
    reason: str | None = None,
) -> list[str]:
    """Reject tools in a lockfile. Returns list of rejected IDs."""
    manager = LockfileManager(lockfile_path)
    if not manager.exists():
        raise FileNotFoundError(f"No lockfile found at: {manager.lockfile_path}")

    manager.load()
    rejected: list[str] = []
    for tid in tool_ids:
        tool = manager.get_tool(tid)
        if tool:
            manager.reject(tool_id=tid, reason=reason)
            rejected.append(tid)
    manager.save()
    return rejected


def run_gate_snapshot(
    lockfile_path: str,
    root_path: str = ".caskmcp",  # noqa: ARG001
) -> str | None:
    """Materialize baseline snapshot. Returns snapshot path or None."""
    manager = LockfileManager(lockfile_path)
    if not manager.exists():
        raise FileNotFoundError(f"No lockfile found at: {manager.lockfile_path}")

    manager.load()
    if manager.get_pending():
        raise ValueError("Cannot snapshot: pending tools exist")

    result = materialize_snapshot(lockfile_path=Path(lockfile_path))
    return str(result.snapshot_dir) if result.snapshot_dir else None


def load_lockfile_tools(lockfile_path: str) -> tuple[Lockfile, list[ToolApproval]]:
    """Load lockfile and return (lockfile, list of all tools)."""
    manager = LockfileManager(lockfile_path)
    if not manager.exists():
        raise FileNotFoundError(f"No lockfile found at: {manager.lockfile_path}")
    lockfile = manager.load()
    return lockfile, list(lockfile.tools.values())


def _try_promote(manager: LockfileManager, _root_path: str) -> bool:
    """Try to promote pending lockfile to approved + seed trust store."""
    try:
        lockfile_path = manager.lockfile_path
        if lockfile_path and "pending" in str(lockfile_path):
            approved_path = Path(str(lockfile_path).replace(".pending.", "."))
            if approved_path != lockfile_path:
                import shutil
                shutil.copy2(lockfile_path, approved_path)
                return True
    except Exception:
        pass
    return False
