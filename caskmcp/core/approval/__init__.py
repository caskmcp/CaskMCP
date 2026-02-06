"""Approval management for CaskMCP tools."""

from caskmcp.core.approval.integrity import (
    compute_artifacts_digest,
    compute_artifacts_digest_from_paths,
    compute_lockfile_digest,
)
from caskmcp.core.approval.lockfile import (
    ApprovalStatus,
    LockfileManager,
    ToolApproval,
)

__all__ = [
    "ApprovalStatus",
    "LockfileManager",
    "ToolApproval",
    "compute_artifacts_digest",
    "compute_artifacts_digest_from_paths",
    "compute_lockfile_digest",
]
