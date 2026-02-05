"""Capture command implementation."""

import sys
from pathlib import Path

import click

from mcpmint.core.capture.har_parser import HARParser
from mcpmint.core.capture.openapi_parser import OpenAPIParser
from mcpmint.core.capture.redactor import Redactor
from mcpmint.storage.filesystem import Storage


def run_capture(
    subcommand: str,
    source: str | None,
    allowed_hosts: list[str],
    name: str | None,
    output: str,
    redact: bool,
    headless: bool,
    script_path: str | None,
    duration_seconds: int,
    verbose: bool,
) -> None:
    """Run the capture command."""
    if subcommand == "import":
        if not source:
            click.echo("Error: SOURCE is required for 'import' subcommand", err=True)
            sys.exit(1)
        _import_har(
            source=source,
            allowed_hosts=allowed_hosts,
            name=name,
            output=output,
            redact=redact,
            verbose=verbose,
        )
    elif subcommand == "record":
        if not source:
            click.echo("Error: URL is required for 'record' subcommand", err=True)
            click.echo("Usage: mcpmint capture record <URL> --allowed-hosts <host>", err=True)
            sys.exit(1)
        _record_playwright(
            start_url=source,
            allowed_hosts=allowed_hosts,
            name=name,
            output=output,
            redact=redact,
            headless=headless,
            script_path=script_path,
            duration_seconds=duration_seconds,
            verbose=verbose,
        )


def run_capture_openapi(
    source: str,
    allowed_hosts: list[str] | None,
    name: str | None,
    output: str,
    verbose: bool,
) -> None:
    """Import an OpenAPI specification.

    Args:
        source: Path to OpenAPI spec file
        allowed_hosts: Optional list of allowed hosts
        name: Optional session name
        output: Output directory
        verbose: Verbose output
    """
    source_path = Path(source)
    if not source_path.exists():
        click.echo(f"Error: OpenAPI spec not found: {source}", err=True)
        sys.exit(1)

    if verbose:
        click.echo(f"Importing OpenAPI spec: {source}")
        if allowed_hosts:
            click.echo(f"Allowed hosts: {', '.join(allowed_hosts)}")

    # Parse OpenAPI
    parser = OpenAPIParser(allowed_hosts=allowed_hosts or [])

    try:
        session = parser.parse_file(source_path, name=name)
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    # Save
    base_path = Path(output)
    if base_path.name == "captures":
        base_path = base_path.parent
    storage = Storage(base_path=base_path)
    capture_path = storage.save_capture(session)

    click.echo(f"Capture saved: {session.id}")
    click.echo(f"  Location: {capture_path}")
    click.echo(f"  Operations: {len(session.exchanges)}")
    click.echo(f"  Source: OpenAPI {source_path.name}")

    if verbose:
        click.echo("\nImport stats:")
        click.echo(f"  Paths: {parser.stats['total_paths']}")
        click.echo(f"  Operations: {parser.stats['total_operations']}")
        click.echo(f"  Imported: {parser.stats['imported']}")
        click.echo(f"  Skipped: {parser.stats['skipped']}")

    if session.warnings:
        click.echo(f"\nWarnings: {len(session.warnings)}")
        if verbose:
            for warning in session.warnings:
                click.echo(f"  - {warning}")


def _import_har(
    source: str,
    allowed_hosts: list[str],
    name: str | None,
    output: str,
    redact: bool,
    verbose: bool,
) -> None:
    """Import a HAR file."""
    source_path = Path(source)
    if not source_path.exists():
        click.echo(f"Error: HAR file not found: {source}", err=True)
        sys.exit(1)

    if verbose:
        click.echo(f"Importing HAR file: {source}")
        click.echo(f"Allowed hosts: {', '.join(allowed_hosts)}")

    # Parse HAR
    parser = HARParser(allowed_hosts=allowed_hosts)
    session = parser.parse_file(source_path, name=name)

    # Redact if enabled
    if redact:
        if verbose:
            click.echo("Applying redaction...")
        redactor = Redactor()
        session = redactor.redact_session(session)

    # Save
    # Note: output is typically .mcpmint/captures, but Storage expects .mcpmint
    # so we go up one level if the output ends with /captures
    base_path = Path(output)
    if base_path.name == "captures":
        base_path = base_path.parent
    storage = Storage(base_path=base_path)
    capture_path = storage.save_capture(session)

    click.echo(f"Capture saved: {session.id}")
    click.echo(f"  Location: {capture_path}")
    click.echo(f"  Exchanges: {len(session.exchanges)}")
    click.echo(f"  Filtered: {session.filtered_requests}")
    if session.warnings:
        click.echo(f"  Warnings: {len(session.warnings)}")
        if verbose:
            for warning in session.warnings:
                click.echo(f"    - {warning}")


def _record_playwright(
    start_url: str,
    allowed_hosts: list[str],
    name: str | None,
    output: str,
    redact: bool,
    headless: bool,
    script_path: str | None,
    duration_seconds: int,
    verbose: bool,
) -> None:
    """Record traffic using Playwright browser automation."""
    try:
        from mcpmint.core.capture.playwright_capture import PlaywrightCapture
    except ImportError:
        click.echo("Error: Playwright is required for capture record mode.", err=True)
        click.echo("Install with: pip install 'mcpmint[playwright]'", err=True)
        sys.exit(1)

    if verbose:
        click.echo(f"Starting Playwright capture: {start_url}")
        click.echo(f"Allowed hosts: {', '.join(allowed_hosts)}")
        click.echo(f"Headless: {headless}")
        if script_path:
            click.echo(f"Scripted capture: {script_path}")
        elif headless:
            click.echo(f"Duration: {duration_seconds}s")

    # Run capture
    try:
        import asyncio

        capture = PlaywrightCapture(allowed_hosts=allowed_hosts, headless=headless)
        session = asyncio.run(
            capture.capture(
                start_url=start_url,
                name=name,
                duration_seconds=duration_seconds if headless and not script_path else None,
                script_path=script_path,
                settle_delay_seconds=1.0 if script_path else 0.0,
            )
        )
    except KeyboardInterrupt:
        click.echo("\nCapture interrupted.")
        sys.exit(0)
    except Exception as e:
        click.echo(f"Error during capture: {e}", err=True)
        sys.exit(1)

    # Redact if enabled
    if redact:
        if verbose:
            click.echo("Applying redaction...")
        redactor = Redactor()
        session = redactor.redact_session(session)

    # Check if we captured anything
    if not session.exchanges:
        click.echo("Warning: No API traffic was captured.", err=True)
        click.echo("Make sure your allowed hosts match the API endpoints.", err=True)
        click.echo(f"Allowed hosts: {', '.join(allowed_hosts)}", err=True)
        sys.exit(1)

    # Save
    base_path = Path(output)
    if base_path.name == "captures":
        base_path = base_path.parent
    storage = Storage(base_path=base_path)
    capture_path = storage.save_capture(session)

    click.echo(f"\nCapture saved: {session.id}")
    click.echo(f"  Location: {capture_path}")
    click.echo(f"  Exchanges: {len(session.exchanges)}")

    if verbose:
        click.echo("\nCapture stats:")
        click.echo(f"  Total requests: {capture.stats['total_requests']}")
        click.echo(f"  Captured: {capture.stats['captured']}")
        click.echo(f"  Filtered (host): {capture.stats['filtered_host']}")
        click.echo(f"  Filtered (static): {capture.stats['filtered_static']}")
        click.echo(f"  Filtered (resource): {capture.stats['filtered_resource_type']}")

    if session.warnings:
        click.echo(f"\nWarnings: {len(session.warnings)}")
        if verbose:
            for warning in session.warnings:
                click.echo(f"  - {warning}")
