"""Reusable prompt primitives for the Cask TUI.

Every function accepts an optional *console* (for output) and *input_stream*
(for deterministic test input) so that tests never need to monkeypatch stdin.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TextIO

from rich.console import Console

from caskmcp.ui.console import err_console


def select_one(
    choices: list[str],
    *,
    labels: list[str] | None = None,
    prompt: str = "Select",
    console: Console | None = None,
    input_stream: TextIO | None = None,
) -> str:
    """Display a numbered menu and return the selected choice value.

    Raises ``KeyboardInterrupt`` on EOF / empty input when no default.
    """
    con = console or err_console
    stream = input_stream or sys.stdin
    display = labels if labels else choices

    con.print()
    for i, label in enumerate(display, 1):
        con.print(f"  [bold]{i}[/bold]) {label}")
    con.print()

    while True:
        con.print(f"{prompt} [muted](1-{len(choices)})[/muted]: ", end="")
        line = stream.readline()
        if not line:
            raise KeyboardInterrupt
        raw = line.strip()
        if not raw:
            continue
        try:
            idx = int(raw)
        except ValueError:
            con.print(f"[warning]Enter a number between 1 and {len(choices)}[/warning]")
            continue
        if 1 <= idx <= len(choices):
            return choices[idx - 1]
        con.print(f"[warning]Enter a number between 1 and {len(choices)}[/warning]")


def select_many(
    choices: list[str],
    *,
    labels: list[str] | None = None,
    prompt: str = "Select (comma-separated numbers, 'all', or 'none')",
    default_all: bool = False,
    console: Console | None = None,
    input_stream: TextIO | None = None,
) -> list[str]:
    """Display a numbered checklist and return selected choice values."""
    con = console or err_console
    stream = input_stream or sys.stdin
    display = labels if labels else choices

    con.print()
    for i, label in enumerate(display, 1):
        con.print(f"  [bold]{i}[/bold]) {label}")
    con.print()

    hint = " [muted](default: all)[/muted]" if default_all else ""
    while True:
        con.print(f"{prompt}{hint}: ", end="")
        line = stream.readline()
        if not line:
            raise KeyboardInterrupt
        raw = line.strip().lower()

        if not raw and default_all:
            return list(choices)
        if raw == "all":
            return list(choices)
        if raw == "none":
            return []

        selected: list[str] = []
        valid = True
        for part in raw.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                idx = int(part)
            except ValueError:
                con.print(f"[warning]Invalid input: {part!r}[/warning]")
                valid = False
                break
            if 1 <= idx <= len(choices):
                if choices[idx - 1] not in selected:
                    selected.append(choices[idx - 1])
            else:
                con.print(
                    f"[warning]{idx} is out of range (1-{len(choices)})[/warning]"
                )
                valid = False
                break
        if valid and selected:
            return selected
        if valid:
            con.print("[warning]No items selected[/warning]")


def confirm(
    message: str,
    *,
    default: bool = False,
    console: Console | None = None,
    input_stream: TextIO | None = None,
) -> bool:
    """Rich-based yes/no confirmation."""
    con = console or err_console
    stream = input_stream or sys.stdin

    hint = "[Y/n]" if default else "[y/N]"
    con.print(f"{message} {hint} ", end="")
    line = stream.readline()
    if not line:
        raise KeyboardInterrupt
    raw = line.strip().lower()
    if not raw:
        return default
    return raw in ("y", "yes")


def confirm_typed(
    message: str,
    *,
    required_text: str = "APPROVE",
    console: Console | None = None,
    input_stream: TextIO | None = None,
) -> bool:
    """Require the user to type an exact string to confirm a risky action."""
    con = console or err_console
    stream = input_stream or sys.stdin

    con.print(f"{message} [warning](type {required_text} to confirm)[/warning]: ", end="")
    line = stream.readline()
    if not line:
        raise KeyboardInterrupt
    return line.strip() == required_text


def input_text(
    prompt: str,
    *,
    default: str = "",
    console: Console | None = None,
    input_stream: TextIO | None = None,
) -> str:
    """Prompt for text input with an optional default."""
    con = console or err_console
    stream = input_stream or sys.stdin

    suffix = f" [muted]({default})[/muted]" if default else ""
    con.print(f"{prompt}{suffix}: ", end="")
    line = stream.readline()
    if not line:
        raise KeyboardInterrupt
    raw = line.strip()
    return raw if raw else default


def input_path(
    prompt: str,
    *,
    must_exist: bool = True,
    file_okay: bool = True,
    dir_okay: bool = True,
    console: Console | None = None,
    input_stream: TextIO | None = None,
) -> Path:
    """Prompt for a file/directory path with validation."""
    con = console or err_console
    stream = input_stream or sys.stdin

    while True:
        con.print(f"{prompt}: ", end="")
        line = stream.readline()
        if not line:
            raise KeyboardInterrupt
        raw = line.strip()
        if not raw:
            con.print("[warning]Path cannot be empty[/warning]")
            continue

        p = Path(raw).expanduser().resolve()

        if must_exist and not p.exists():
            con.print(f"[warning]Path does not exist: {p}[/warning]")
            continue
        if p.exists():
            if p.is_file() and not file_okay:
                con.print("[warning]Expected a directory, got a file[/warning]")
                continue
            if p.is_dir() and not dir_okay:
                con.print("[warning]Expected a file, got a directory[/warning]")
                continue

        return p
