"""Serve command implementation."""

import click


def run_serve(
    port: int,
    artifacts_dir: str,
    host: str,
    verbose: bool,  # noqa: ARG001 - Will be used when serve is implemented
) -> None:
    """Run the serve command (stub)."""
    raise click.ClickException(
        "The dashboard command is not implemented yet. "
        f"Requested host={host} port={port} artifacts_dir={artifacts_dir}"
    )
