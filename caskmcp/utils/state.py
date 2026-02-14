"""Shared filesystem state path helpers."""

from __future__ import annotations

from pathlib import Path

DEFAULT_ROOT = Path(".caskmcp")


def resolve_root(root: str | Path | None = None) -> Path:
    """Resolve the canonical state root path."""
    if root is None:
        return DEFAULT_ROOT
    return Path(root)


def root_path(root: str | Path | None, *parts: str) -> Path:
    """Resolve a child path within the canonical state root."""
    resolved = resolve_root(root)
    for part in parts:
        resolved = resolved / part
    return resolved


def confirmation_store_path(root: str | Path | None) -> Path:
    """Return default confirmation store path for a root."""
    return root_path(root, "state", "confirmations.db")


def runtime_lock_path(root: str | Path | None) -> Path:
    """Return default command lock path for a root."""
    return root_path(root, "state", "lock")
