"""TUI interaction policy: when to show interactive prompts.

Rules (checked in order):
1. Explicit force parameter → honour it.
2. Machine-output mode → False.
3. Known CI env vars → False.
4. TERM=dumb → False.
5. stdin is not a TTY → False (prevents Prompt.ask hang on piped stdin).
6. stderr is not a TTY (Rich detection) → False.
7. All pass → True.
"""

from __future__ import annotations

import os
import sys
from functools import lru_cache

from rich.console import Console

_CI_ENV_VARS = frozenset({
    "CI",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "JENKINS_URL",
    "TF_BUILD",
    "BUILDKITE",
    "CIRCLECI",
    "TRAVIS",
    "CASK_NON_INTERACTIVE",
})


def should_interact(
    *,
    force: bool | None = None,
    machine_output: bool = False,
) -> bool:
    """Return True if the current session should use interactive prompts."""
    if force is not None:
        return force

    if machine_output:
        return False

    for var in _CI_ENV_VARS:
        if os.environ.get(var):
            return False

    if os.environ.get("TERM") == "dumb":
        return False

    if not _stdin_is_tty():
        return False

    return _stderr_is_terminal()


@lru_cache(maxsize=1)
def _stdin_is_tty() -> bool:
    """Check whether stdin is a real TTY."""
    return sys.stdin.isatty()


@lru_cache(maxsize=1)
def _stderr_is_terminal() -> bool:
    """Use Rich Console to detect stderr terminal capability."""
    c = Console(stderr=True)
    return c.is_terminal
