"""Main CLI entry point for CaskMCP."""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

import click

from caskmcp import __version__
from caskmcp.branding import (
    CLI_PRIMARY_COMMAND,
    PRODUCT_NAME,
)
from caskmcp.utils.locks import RootLockError, clear_root_lock, root_command_lock
from caskmcp.utils.state import confirmation_store_path, resolve_root

ADVANCED_TOP_LEVEL_COMMANDS = {
    "capture",
    "openapi",
    "compile",
    "demo",
    "config",
    "migrate",
    "lint",
    "enforce",
    "confirm",
    "bundle",
    "doctor",
    "compliance",
    "scopes",
    "state",
}


def _render_help_all(ctx: click.Context) -> str:
    """Render top-level help including hidden advanced commands."""
    command = ctx.command
    if not isinstance(command, click.Group):
        return ctx.get_help()

    formatter = ctx.make_formatter()
    command.format_usage(ctx, formatter)
    command.format_help_text(ctx, formatter)
    command.format_options(ctx, formatter)
    with formatter.section("All Commands"):
        formatter.write_dl(
            [
                (name, command.commands[name].get_short_help_str())
                for name in sorted(command.commands)
            ]
        )
    return formatter.getvalue().rstrip("\n")


def _show_help_all(
    ctx: click.Context,
    _param: click.Parameter,
    value: bool,
) -> None:
    """Eager callback for --help-all."""
    if not value or ctx.resilient_parsing:
        return
    click.echo(_render_help_all(ctx))
    ctx.exit()


@click.group()
@click.version_option(version=__version__, prog_name=CLI_PRIMARY_COMMAND)
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose output")
@click.option(
    "--help-all",
    is_flag=True,
    is_eager=True,
    expose_value=False,
    callback=_show_help_all,
    help="Show help including advanced commands",
)
@click.option(
    "--root",
    type=click.Path(file_okay=False, path_type=Path),
    default=resolve_root(),
    show_default=True,
    help="Canonical state root for captures, artifacts, reports, and locks",
)
@click.pass_context
def cli(ctx: click.Context, verbose: bool, root: Path) -> None:
    """Turn observed web/API traffic into a safe-by-default MCP server."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["root"] = root
    ctx.obj["brand"] = {
        "product": PRODUCT_NAME,
        "primary_command": CLI_PRIMARY_COMMAND,
    }


def _default_root_path(ctx: click.Context, *parts: str) -> Path:
    root = ctx.obj.get("root", resolve_root())
    return Path(root, *parts)


def _run_with_lock(
    ctx: click.Context,
    command: str,
    callback: Callable[[], None],
    *,
    lock_id: str | None = None,
) -> None:
    try:
        with root_command_lock(
            ctx.obj.get("root", resolve_root()),
            command,
            lock_id=lock_id,
        ):
            callback()
    except RootLockError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)


@cli.command()
@click.argument("subcommand", type=click.Choice(["import", "record"]))
@click.argument("source", required=False)
@click.option(
    "--allowed-hosts",
    "-a",
    multiple=True,
    required=True,
    help="Hosts to include (required, repeatable)",
)
@click.option("--name", "-n", help="Name for the capture session")
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Capture output directory (defaults to <root>/captures)",
)
@click.option(
    "--input-format",
    type=click.Choice(["har", "otel"]),
    default="har",
    show_default=True,
    help="Input format for import mode",
)
@click.option("--no-redact", is_flag=True, help="Disable redaction (not recommended)")
@click.option(
    "--headless/--no-headless",
    default=False,
    show_default=True,
    help="Run Playwright browser headless in record mode",
)
@click.option(
    "--script",
    type=click.Path(exists=True),
    help="Python script with async run(page, context) for scripted capture",
)
@click.option(
    "--duration",
    type=int,
    default=30,
    show_default=True,
    help="Capture duration in seconds for non-interactive/headless mode",
)
@click.option(
    "--load-storage-state",
    type=click.Path(exists=True),
    help="Load browser storage state (cookies, localStorage) from a JSON file",
)
@click.option(
    "--save-storage-state",
    type=click.Path(),
    help="Save browser storage state to a JSON file after capture",
)
@click.pass_context
def capture(
    ctx: click.Context,
    subcommand: str,
    source: str | None,
    allowed_hosts: tuple[str, ...],
    name: str | None,
    output: str | None,
    input_format: str,
    no_redact: bool,
    headless: bool,
    script: str | None,
    duration: int,
    load_storage_state: str | None,
    save_storage_state: str | None,
) -> None:
    """Import traffic from HAR files or capture with Playwright.

    For 'import': SOURCE is the path to a HAR file.
    For 'record': SOURCE is the starting URL for browser capture.

    \b
    Examples:
      # Import a HAR file
      caskmcp capture import traffic.har --allowed-hosts api.example.com

      # Import OpenTelemetry traces (OTLP JSON/NDJSON export)
      caskmcp capture import traces.json --input-format otel --allowed-hosts api.example.com

      # Record traffic interactively with Playwright
      caskmcp capture record https://example.com --allowed-hosts api.example.com

      # Record with pre-authenticated session
      caskmcp capture record https://example.com -a api.example.com \\
        --load-storage-state auth-state.json

    Record mode supports interactive (`--no-headless`), timed headless
    capture (`--headless --duration`), and scripted automation (`--script`).
    """
    from caskmcp.cli.capture import run_capture

    resolved_output = output or str(_default_root_path(ctx, "captures"))

    _run_with_lock(
        ctx,
        "capture",
        lambda: run_capture(
            subcommand=subcommand,
            source=source,
            input_format=input_format,
            allowed_hosts=list(allowed_hosts),
            name=name,
            output=resolved_output,
            redact=not no_redact,
            headless=headless,
            script_path=script,
            duration_seconds=duration,
            load_storage_state=load_storage_state,
            save_storage_state=save_storage_state,
            verbose=ctx.obj.get("verbose", False),
            root_path=str(ctx.obj.get("root", resolve_root())),
        ),
    )


@cli.command()
@click.argument("start_url")
@click.option(
    "--allowed-hosts",
    "-a",
    multiple=True,
    required=True,
    help="Hosts to include (required, repeatable)",
)
@click.option("--name", "-n", help="Optional toolpack/session name")
@click.option(
    "--scope",
    "-s",
    default="agent_safe_readonly",
    show_default=True,
    help="Scope to apply during compile",
)
@click.option(
    "--headless/--no-headless",
    default=True,
    show_default=True,
    help="Run browser headless during capture",
)
@click.option(
    "--script",
    type=click.Path(exists=True),
    help="Python script with async run(page, context) for scripted capture",
)
@click.option(
    "--duration",
    type=int,
    default=30,
    show_default=True,
    help="Capture duration in seconds when no script is provided",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output root directory (defaults to --root)",
)
@click.option(
    "--deterministic/--volatile-metadata",
    default=True,
    show_default=True,
    help="Deterministic metadata by default; use --volatile-metadata for ephemeral IDs/timestamps",
)
@click.option(
    "--runtime",
    type=click.Choice(["local", "container"]),
    default="local",
    show_default=True,
    help="Runtime mode metadata/emission (container emits runtime files)",
)
@click.option(
    "--runtime-build",
    is_flag=True,
    help="Build container image after emitting runtime files (requires Docker)",
)
@click.option(
    "--runtime-tag",
    help="Container image tag to use when --runtime=container",
)
@click.option(
    "--runtime-version-pin",
    help="Exact requirement line for caskmcp runtime when --runtime=container",
)
@click.option(
    "--print-mcp-config",
    is_flag=True,
    help="Print a ready-to-paste Claude Desktop MCP config snippet",
)
@click.option(
    "--auth-profile",
    default=None,
    help="Auth profile name to use for authenticated capture",
)
@click.option(
    "--webmcp",
    is_flag=True,
    default=False,
    help="Discover WebMCP tools (navigator.modelContext) on the target page",
)
@click.option(
    "--redaction-profile",
    type=click.Choice(["default_safe", "high_risk_pii"]),
    default=None,
    help="Redaction profile to apply during capture (default: built-in patterns)",
)
@click.pass_context
def mint(
    ctx: click.Context,
    start_url: str,
    allowed_hosts: tuple[str, ...],
    name: str | None,
    scope: str,
    headless: bool,
    script: str | None,
    duration: int,
    output: str | None,
    deterministic: bool,
    runtime: str,
    runtime_build: bool,
    runtime_tag: str | None,
    runtime_version_pin: str | None,
    print_mcp_config: bool,
    auth_profile: str | None,
    webmcp: bool,
    redaction_profile: str | None,
) -> None:
    """Capture traffic and mint a first-class toolpack for MCP serving.

    \b
    Example:
      caskmcp mint https://example.com -a api.example.com --print-mcp-config
      caskmcp mint https://app.example.com -a api.example.com --auth-profile myapp
      caskmcp mint https://app.example.com --webmcp -a api.example.com
    """
    from click.core import ParameterSource

    from caskmcp.cli.mint import run_mint

    # When --allowed-hosts is explicitly provided but --scope is not,
    # default to first_party_only (includes POST/PUT/DELETE).
    # agent_safe_readonly excludes writes, which is unhelpful when the
    # user has explicitly allowed a host.
    effective_scope = scope
    scope_source = ctx.get_parameter_source("scope")
    if scope_source != ParameterSource.COMMANDLINE and allowed_hosts:
        effective_scope = "first_party_only"

    resolved_output = output or str(ctx.obj.get("root", resolve_root()))

    _run_with_lock(
        ctx,
        "mint",
        lambda: run_mint(
            start_url=start_url,
            allowed_hosts=list(allowed_hosts),
            name=name,
            scope_name=effective_scope,
            headless=headless,
            script_path=script,
            duration_seconds=duration,
            output_root=resolved_output,
            deterministic=deterministic,
            runtime_mode=runtime,
            runtime_build=runtime_build,
            runtime_tag=runtime_tag,
            runtime_version_pin=runtime_version_pin,
            print_mcp_config=print_mcp_config,
            auth_profile=auth_profile,
            webmcp=webmcp,
            redaction_profile=redaction_profile,
            verbose=ctx.obj.get("verbose", False),
        ),
    )


@cli.command()
@click.option(
    "--out",
    type=click.Path(file_okay=False),
    help="Output root directory (defaults to a temporary directory)",
)
@click.pass_context
def demo(ctx: click.Context, out: str | None) -> None:
    """Generate a deterministic offline demo toolpack from bundled fixture traffic."""
    from caskmcp.cli.demo import run_demo

    _run_with_lock(
        ctx,
        "demo",
        lambda: run_demo(
            output_root=out or str(ctx.obj.get("root", resolve_root())),
            verbose=ctx.obj.get("verbose", False),
        ),
    )


@cli.command()
@click.option(
    "--toolpack",
    required=True,
    type=click.Path(exists=True),
    help="Path to toolpack.yaml",
)
@click.option(
    "--name",
    help="Override the MCP server name (defaults to toolpack_id)",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "yaml", "codex"]),
    default="json",
    show_default=True,
    help="Output format for config snippet",
)
def config(toolpack: str, name: str | None, output_format: str) -> None:
    """Print a ready-to-paste MCP client config snippet."""
    from caskmcp.cli.config import run_config

    run_config(toolpack_path=toolpack, fmt=output_format, name_override=name)


@cli.command()
@click.option(
    "--toolpack",
    required=True,
    type=click.Path(exists=True),
    help="Path to toolpack.yaml",
)
@click.option(
    "--runtime",
    type=click.Choice(["auto", "local", "container"]),
    default="auto",
    show_default=True,
    help="Runtime to validate",
)
@click.pass_context
def doctor(ctx: click.Context, toolpack: str, runtime: str) -> None:
    """Validate toolpack readiness for execution."""
    from click.core import ParameterSource

    from caskmcp.cli.doctor import run_doctor

    runtime_source = ctx.get_parameter_source("runtime")
    require_local_mcp = (
        runtime == "local" and runtime_source == ParameterSource.COMMANDLINE
    )

    run_doctor(
        toolpack_path=toolpack,
        runtime=runtime,
        verbose=ctx.obj.get("verbose", False),
        require_local_mcp=require_local_mcp,
    )


@cli.command()
@click.option(
    "--toolpack",
    required=True,
    type=click.Path(exists=True),
    help="Path to toolpack.yaml",
)
@click.option(
    "--runtime",
    type=click.Choice(["auto", "local", "container"]),
    default="auto",
    show_default=True,
    help="Runtime to use",
)
@click.option(
    "--print-config-and-exit",
    is_flag=True,
    help="Print MCP config snippet to stdout and exit",
)
@click.option(
    "--toolset",
    help="Named toolset to expose (optional)",
)
@click.option(
    "--lockfile",
    type=click.Path(),
    help="Path to approved lockfile (required by default unless --unsafe-no-lockfile)",
)
@click.option(
    "--base-url",
    help="Base URL for upstream API (overrides manifest hosts)",
)
@click.option(
    "--auth",
    "auth_header",
    help="Authorization header value for upstream requests",
)
@click.option(
    "--audit-log",
    type=click.Path(),
    help="Path for audit log file",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Evaluate policy but don't execute upstream calls",
)
@click.option(
    "--confirm-store",
    type=click.Path(),
    help="Path to local out-of-band confirmation store",
)
@click.option(
    "--allow-private-cidr",
    "allow_private_cidrs",
    multiple=True,
    help="Allow private CIDR targets (repeatable; default denies private ranges)",
)
@click.option(
    "--allow-redirects",
    is_flag=True,
    help="Allow redirects (each hop is re-validated against allowlists)",
)
@click.option(
    "--unsafe-no-lockfile",
    is_flag=True,
    help="Allow runtime without approved lockfile (unsafe escape hatch)",
)
@click.pass_context
def run(
    ctx: click.Context,
    toolpack: str,
    runtime: str,
    print_config_and_exit: bool,
    toolset: str | None,
    lockfile: str | None,
    base_url: str | None,
    auth_header: str | None,
    audit_log: str | None,
    dry_run: bool,
    confirm_store: str | None,
    allow_private_cidrs: tuple[str, ...],
    allow_redirects: bool,
    unsafe_no_lockfile: bool,
) -> None:
    """Run a toolpack locally or in a container runtime."""
    from caskmcp.cli.run import run_run

    resolved_confirm_store = confirm_store or str(
        confirmation_store_path(ctx.obj.get("root", resolve_root()))
    )

    _run_with_lock(
        ctx,
        "run",
        lambda: run_run(
            toolpack_path=toolpack,
            runtime=runtime,
            print_config_and_exit=print_config_and_exit,
            toolset=toolset,
            lockfile=lockfile,
            base_url=base_url,
            auth_header=auth_header,
            audit_log=audit_log,
            dry_run=dry_run,
            confirm_store=resolved_confirm_store,
            allow_private_cidrs=list(allow_private_cidrs),
            allow_redirects=allow_redirects,
            unsafe_no_lockfile=unsafe_no_lockfile,
            verbose=ctx.obj.get("verbose", False),
        ),
        lock_id=str(Path(toolpack).resolve()),
    )


def _run_diff_report(
    *,
    toolpack: str,
    baseline: str | None,
    output: str | None,
    output_format: str,
    root_path: str,
    verbose: bool,
) -> None:
    from caskmcp.cli.plan import run_plan

    run_plan(
        toolpack_path=toolpack,
        baseline=baseline,
        output_dir=output,
        output_format=output_format,
        root_path=root_path,
        verbose=verbose,
    )


@cli.command("diff")
@click.option(
    "--toolpack",
    required=True,
    type=click.Path(exists=True),
    help="Path to toolpack.yaml",
)
@click.option(
    "--baseline",
    type=click.Path(),
    help="Baseline toolpack.yaml or snapshot directory",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output directory for diff artifacts",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "markdown", "github-md", "both"]),
    default="both",
    show_default=True,
    help="Diff output format",
)
@click.pass_context
def diff(
    ctx: click.Context,
    toolpack: str,
    baseline: str | None,
    output: str | None,
    output_format: str,
) -> None:
    """Generate a deterministic diff report."""
    _run_diff_report(
        toolpack=toolpack,
        baseline=baseline,
        output=output,
        output_format=output_format,
        root_path=str(ctx.obj.get("root", resolve_root())),
        verbose=ctx.obj.get("verbose", False),
    )


@cli.command("plan")
@click.option(
    "--toolpack",
    required=True,
    type=click.Path(exists=True),
    help="Path to toolpack.yaml",
)
@click.option(
    "--baseline",
    type=click.Path(),
    help="Baseline toolpack.yaml or snapshot directory",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output directory for plan artifacts",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "markdown", "github-md", "both"]),
    default="both",
    show_default=True,
    help="Plan output format",
)
@click.pass_context
def plan(
    ctx: click.Context,
    toolpack: str,
    baseline: str | None,
    output: str | None,
    output_format: str,
) -> None:
    """Alias for `caskmcp diff`."""
    _run_diff_report(
        toolpack=toolpack,
        baseline=baseline,
        output=output,
        output_format=output_format,
        root_path=str(ctx.obj.get("root", resolve_root())),
        verbose=ctx.obj.get("verbose", False),
    )


@cli.command()
@click.option(
    "--toolpack",
    required=True,
    type=click.Path(exists=True),
    help="Path to toolpack.yaml",
)
@click.option(
    "--out",
    "output",
    required=True,
    type=click.Path(),
    help="Output bundle zip path",
)
@click.pass_context
def bundle(ctx: click.Context, toolpack: str, output: str) -> None:
    """Create a deterministic toolpack bundle."""
    from caskmcp.cli.bundle import run_bundle

    run_bundle(
        toolpack_path=toolpack,
        output_path=output,
        verbose=ctx.obj.get("verbose", False),
    )


@cli.command("openapi")
@click.argument("source", type=click.Path(exists=True))
@click.option(
    "--allowed-hosts",
    "-a",
    multiple=True,
    help="Hosts to include (optional - defaults to spec servers)",
)
@click.option("--name", "-n", help="Name for the capture session")
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output directory (defaults to <root>/captures)",
)
@click.pass_context
def openapi_import(
    ctx: click.Context,
    source: str,
    allowed_hosts: tuple[str, ...],
    name: str | None,
    output: str | None,
) -> None:
    """Import an OpenAPI specification as a capture.

    This creates a capture session from an existing OpenAPI 3.x spec,
    allowing you to bootstrap tools from documented APIs.

    \b
    Examples:
      caskmcp openapi api-spec.yaml
      caskmcp openapi openapi.json --name "My API"
      caskmcp openapi spec.yaml --allowed-hosts api.example.com
    """
    from caskmcp.cli.capture import run_capture_openapi

    resolved_output = output or str(_default_root_path(ctx, "captures"))
    _run_with_lock(
        ctx,
        "openapi",
        lambda: run_capture_openapi(
            source=source,
            allowed_hosts=list(allowed_hosts) if allowed_hosts else None,
            name=name,
            output=resolved_output,
            verbose=ctx.obj.get("verbose", False),
            root_path=str(ctx.obj.get("root", resolve_root())),
        ),
    )


@cli.command()
@click.option("--capture", "-c", required=True, help="Capture session ID or path")
@click.option(
    "--scope",
    "-s",
    default="first_party_only",
    help="Scope to apply (default: first_party_only)",
)
@click.option("--scope-file", type=click.Path(exists=True), help="Path to custom scope YAML")
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["manifest", "openapi", "all"]),
    default="all",
    help="Output format",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output directory (defaults to <root>/artifacts)",
)
@click.option(
    "--deterministic/--volatile-metadata",
    default=True,
    show_default=True,
    help="Deterministic artifacts by default; use --volatile-metadata for ephemeral IDs/timestamps",
)
@click.pass_context
def compile(
    ctx: click.Context,
    capture: str,
    scope: str,
    scope_file: str | None,
    output_format: str,
    output: str | None,
    deterministic: bool,
) -> None:
    """Compile captured traffic into contracts, tools, and policies.

    \b
    Examples:
      caskmcp compile --capture cap_20240204_abc123 --scope agent_safe_readonly
      caskmcp compile --capture ./captures/session.json --format manifest
    """
    from caskmcp.cli.compile import run_compile

    resolved_output = output or str(_default_root_path(ctx, "artifacts"))

    _run_with_lock(
        ctx,
        "compile",
        lambda: run_compile(
            capture_id=capture,
            scope_name=scope,
            scope_file=scope_file,
            output_format=output_format,
            output_dir=resolved_output,
            verbose=ctx.obj.get("verbose", False),
            deterministic=deterministic,
            root_path=str(ctx.obj.get("root", resolve_root())),
        ),
    )


@cli.command()
@click.option("--from", "from_capture", help="Source capture ID")
@click.option("--to", "to_capture", help="Target capture ID")
@click.option("--baseline", type=click.Path(exists=True), help="Baseline file path")
@click.option("--capture-id", help="Capture ID to compare against baseline")
@click.option("--capture-path", type=click.Path(), help="Capture path to compare against baseline")
@click.option(
    "--capture",
    "-c",
    "capture_legacy",
    help="Deprecated alias for --capture-id/--capture-path",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output directory (defaults to <root>/reports)",
)
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["json", "markdown", "both"]),
    default="both",
    help="Report format",
)
@click.option(
    "--deterministic/--volatile-metadata",
    default=True,
    show_default=True,
    help="Deterministic drift output by default; use --volatile-metadata for ephemeral IDs/timestamps",
)
@click.pass_context
def drift(
    ctx: click.Context,
    from_capture: str | None,
    to_capture: str | None,
    baseline: str | None,
    capture_id: str | None,
    capture_path: str | None,
    capture_legacy: str | None,
    output: str | None,
    output_format: str,
    deterministic: bool,
) -> None:
    """Detect drift between captures or against a baseline.

    \b
    Examples:
      caskmcp drift --from cap_old --to cap_new
      caskmcp drift --from cap_old --to cap_new --volatile-metadata
      caskmcp drift --baseline baseline.json --capture cap_new
    """
    from caskmcp.cli.drift import run_drift

    if capture_legacy:
        if capture_id or capture_path:
            click.echo(
                "Error: --capture cannot be used with --capture-id or --capture-path",
                err=True,
            )
            sys.exit(1)
        if Path(capture_legacy).exists():
            capture_path = capture_legacy
        else:
            capture_id = capture_legacy

    resolved_output = output or str(_default_root_path(ctx, "reports"))

    run_drift(
        from_capture=from_capture,
        to_capture=to_capture,
        baseline=baseline,
        capture_id=capture_id,
        capture_path=capture_path,
        output_dir=resolved_output,
        output_format=output_format,
        verbose=ctx.obj.get("verbose", False),
        deterministic=deterministic,
        root_path=str(ctx.obj.get("root", resolve_root())),
    )


@cli.command()
@click.option(
    "--toolpack",
    required=True,
    type=click.Path(exists=True),
    help="Path to toolpack.yaml",
)
@click.option(
    "--mode",
    type=click.Choice(["contracts", "replay", "outcomes", "provenance", "all"]),
    default="all",
    show_default=True,
    help="Verification mode",
)
@click.option("--lockfile", type=click.Path(), help="Optional lockfile override (pending allowed)")
@click.option("--playbook", type=click.Path(exists=True), help="Path to deterministic playbook")
@click.option("--ui-assertions", type=click.Path(exists=True), help="Path to UI assertion list")
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output directory for verification reports (defaults to <root>/reports)",
)
@click.option("--strict/--no-strict", default=True, show_default=True, help="Strict gating mode")
@click.option("--top-k", default=5, show_default=True, type=int, help="Top candidate APIs per assertion")
@click.option(
    "--min-confidence",
    default=0.70,
    show_default=True,
    type=float,
    help="Minimum confidence threshold for provenance pass",
)
@click.option(
    "--unknown-budget",
    default=0.20,
    show_default=True,
    type=float,
    help="Maximum ratio of unknown provenance assertions before gating",
)
@click.pass_context
def verify(
    ctx: click.Context,
    toolpack: str,
    mode: str,
    lockfile: str | None,
    playbook: str | None,
    ui_assertions: str | None,
    output: str | None,
    strict: bool,
    top_k: int,
    min_confidence: float,
    unknown_budget: float,
) -> None:
    """Run verification (contracts/replay/outcomes/provenance)."""
    from caskmcp.cli.verify import run_verify

    resolved_output = output or str(_default_root_path(ctx, "reports"))
    run_verify(
        toolpack_path=toolpack,
        mode=mode,
        lockfile_path=lockfile,
        playbook_path=playbook,
        ui_assertions_path=ui_assertions,
        output_dir=resolved_output,
        strict=strict,
        top_k=top_k,
        min_confidence=min_confidence,
        unknown_budget=unknown_budget,
        verbose=ctx.obj.get("verbose", False),
    )


@cli.command()
@click.option(
    "--toolpack",
    type=click.Path(exists=True),
    help="Path to toolpack.yaml (resolves tools/policy paths)",
)
@click.option("--tools", type=click.Path(exists=True), help="Path to tools.json")
@click.option("--policy", type=click.Path(exists=True), help="Path to policy.yaml")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
    help="Lint output format",
)
@click.pass_context
def lint(
    ctx: click.Context,
    toolpack: str | None,
    tools: str | None,
    policy: str | None,
    output_format: str,
) -> None:
    """Lint capability artifacts for strict governance hygiene."""
    from caskmcp.cli.lint import run_lint

    run_lint(
        toolpack_path=toolpack,
        tools_path=tools,
        policy_path=policy,
        output_format=output_format,
        verbose=ctx.obj.get("verbose", False),
    )


@cli.command()
@click.option("--tools", "-t", required=True, type=click.Path(exists=True), help="Tool manifest")
@click.option(
    "--toolsets",
    type=click.Path(exists=True),
    help="Path to toolsets.yaml artifact (optional)",
)
@click.option(
    "--toolset",
    help="Named toolset to enforce (optional, defaults to all tools)",
)
@click.option("--policy", "-p", required=True, type=click.Path(exists=True), help="Policy file")
@click.option(
    "--lockfile",
    type=click.Path(exists=True),
    help="Approval lockfile for runtime gating (required in proxy mode unless --unsafe-no-lockfile)",
)
@click.option("--port", default=8081, help="Port for gateway")
@click.option("--audit-log", type=click.Path(), help="Path for audit log")
@click.option("--dry-run", is_flag=True, help="Evaluate but don't execute")
@click.option(
    "--mode", "-m",
    type=click.Choice(["evaluate", "proxy"]),
    default="evaluate",
    help="Mode: evaluate (policy only) or proxy (forward to upstream)",
)
@click.option(
    "--base-url",
    help="Base URL for upstream API (proxy mode)",
)
@click.option(
    "--auth",
    "auth_header",
    help="Authorization header for upstream requests (proxy mode)",
)
@click.option(
    "--confirm-store",
    type=click.Path(),
    help="Path to local out-of-band confirmation store",
)
@click.option(
    "--allow-private-cidr",
    "allow_private_cidrs",
    multiple=True,
    help="Allow private CIDR targets (repeatable; default denies private ranges)",
)
@click.option(
    "--allow-redirects",
    is_flag=True,
    help="Allow redirects (each hop is re-validated against allowlists)",
)
@click.option(
    "--unsafe-no-lockfile",
    is_flag=True,
    help="Allow proxy mode without lockfile approvals/integrity gating (unsafe escape hatch)",
)
@click.pass_context
def enforce(
    ctx: click.Context,
    tools: str,
    toolsets: str | None,
    toolset: str | None,
    policy: str,
    lockfile: str | None,
    port: int,
    audit_log: str | None,
    dry_run: bool,
    mode: str,
    base_url: str | None,
    auth_header: str | None,
    confirm_store: str | None,
    allow_private_cidrs: tuple[str, ...],
    allow_redirects: bool,
    unsafe_no_lockfile: bool,
) -> None:
    """Run as a gateway for tool calls with policy enforcement.

    In 'evaluate' mode (default), the gateway evaluates policy and returns
    allow/deny decisions without making upstream requests.

    In 'proxy' mode, the gateway evaluates policy AND forwards allowed
    requests to the upstream API, returning real responses.

    \b
    Examples:
      # Evaluate mode (policy decisions only)
      caskmcp enforce --tools tools.json --policy policy.yaml

      # Enforce using a curated toolset
      caskmcp enforce --tools tools.json --toolsets toolsets.yaml --toolset readonly --policy policy.yaml

      # Proxy mode (forward to upstream, lockfile required by default)
      caskmcp enforce --tools tools.json --policy policy.yaml \\
        --mode=proxy --base-url https://api.example.com --auth "Bearer token" \\
        --lockfile caskmcp.lock.yaml

      # Proxy mode with dry run (evaluate but don't execute)
      caskmcp enforce --tools tools.json --policy policy.yaml \\
        --mode=proxy --base-url https://api.example.com --dry-run \\
        --lockfile caskmcp.lock.yaml
    """
    from caskmcp.cli.enforce import run_enforce

    resolved_confirm_store = confirm_store or str(
        confirmation_store_path(ctx.obj.get("root", resolve_root()))
    )

    _run_with_lock(
        ctx,
        "enforce",
        lambda: run_enforce(
            tools_path=tools,
            toolsets_path=toolsets,
            toolset_name=toolset,
            policy_path=policy,
            port=port,
            audit_log=audit_log,
            dry_run=dry_run,
            verbose=ctx.obj.get("verbose", False),
            mode=mode,
            base_url=base_url,
            auth_header=auth_header,
            lockfile_path=lockfile,
            confirmation_store_path=resolved_confirm_store,
            allow_private_cidrs=list(allow_private_cidrs),
            allow_redirects=allow_redirects,
            unsafe_no_lockfile=unsafe_no_lockfile,
        ),
    )


@cli.command()
@click.option(
    "--tools", "-t",
    type=click.Path(),
    help="Path to tools.json manifest",
)
@click.option(
    "--toolpack",
    type=click.Path(exists=True),
    help="Path to toolpack.yaml (resolves manifest/policy/toolsets paths)",
)
@click.option(
    "--toolsets",
    type=click.Path(),
    help="Path to toolsets.yaml (defaults to sibling of --tools if present)",
)
@click.option(
    "--toolset",
    help="Named toolset to expose (defaults to readonly when toolsets.yaml exists)",
)
@click.option(
    "--policy", "-p",
    type=click.Path(),
    help="Path to policy.yaml (optional)",
)
@click.option(
    "--lockfile", "-l",
    type=click.Path(),
    help="Path to approved lockfile (required by default unless --unsafe-no-lockfile)",
)
@click.option(
    "--base-url",
    help="Base URL for upstream API (overrides manifest hosts)",
)
@click.option(
    "--auth",
    "auth_header",
    help="Authorization header value for upstream requests",
)
@click.option(
    "--audit-log",
    type=click.Path(),
    help="Path for audit log file",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Evaluate policy but don't execute upstream calls",
)
@click.option(
    "--confirm-store",
    type=click.Path(),
    help="Path to local out-of-band confirmation store",
)
@click.option(
    "--allow-private-cidr",
    "allow_private_cidrs",
    multiple=True,
    help="Allow private CIDR targets (repeatable; default denies private ranges)",
)
@click.option(
    "--allow-redirects",
    is_flag=True,
    help="Allow redirects (each hop is re-validated against allowlists)",
)
@click.option(
    "--unsafe-no-lockfile",
    is_flag=True,
    help="Allow runtime without approved lockfile (unsafe escape hatch)",
)
@click.pass_context
def serve(
    ctx: click.Context,
    tools: str | None,
    toolpack: str | None,
    toolsets: str | None,
    toolset: str | None,
    policy: str | None,
    lockfile: str | None,
    base_url: str | None,
    auth_header: str | None,
    audit_log: str | None,
    dry_run: bool,
    confirm_store: str | None,
    allow_private_cidrs: tuple[str, ...],
    allow_redirects: bool,
    unsafe_no_lockfile: bool,
) -> None:
    """Alias for `caskmcp mcp serve`.

    This command exists for convenience and forwards to MCP server runtime.
    """
    click.echo(
        "Notice: `caskmcp serve` is an alias for `caskmcp mcp serve`.",
        err=True,
    )

    resolved_confirm_store = confirm_store or str(
        confirmation_store_path(ctx.obj.get("root", resolve_root()))
    )

    from caskmcp.cli.mcp import run_mcp_serve

    lock_id = None
    if toolpack:
        lock_id = f"toolpack:{Path(toolpack).resolve()}"
    elif tools:
        lock_id = f"tools:{Path(tools).resolve()}"

    _run_with_lock(
        ctx,
        "serve",
        lambda: run_mcp_serve(
            tools_path=tools,
            toolpack_path=toolpack,
            toolsets_path=toolsets,
            toolset_name=toolset,
            policy_path=policy,
            lockfile_path=lockfile,
            base_url=base_url,
            auth_header=auth_header,
            audit_log=audit_log,
            dry_run=dry_run,
            confirmation_store_path=resolved_confirm_store,
            allow_private_cidrs=list(allow_private_cidrs),
            allow_redirects=allow_redirects,
            unsafe_no_lockfile=unsafe_no_lockfile,
            verbose=ctx.obj.get("verbose", False),
        ),
        lock_id=lock_id,
    )


@cli.group()
def mcp() -> None:
    """MCP server commands for exposing tools to AI agents.

    The MCP (Model Context Protocol) server exposes your compiled tools
    as callable actions that AI agents like Claude can use safely.
    """
    pass


@mcp.command("serve")
@click.option(
    "--tools", "-t",
    type=click.Path(),
    help="Path to tools.json manifest",
)
@click.option(
    "--toolpack",
    type=click.Path(exists=True),
    help="Path to toolpack.yaml (resolves manifest/policy/toolsets paths)",
)
@click.option(
    "--toolsets",
    type=click.Path(),
    help="Path to toolsets.yaml (defaults to sibling of --tools if present)",
)
@click.option(
    "--toolset",
    help="Named toolset to expose (defaults to readonly when toolsets.yaml exists)",
)
@click.option(
    "--policy", "-p",
    type=click.Path(),
    help="Path to policy.yaml (optional)",
)
@click.option(
    "--lockfile", "-l",
    type=click.Path(),
    help="Path to approved lockfile (required by default unless --unsafe-no-lockfile)",
)
@click.option(
    "--base-url",
    help="Base URL for upstream API (overrides manifest hosts)",
)
@click.option(
    "--auth",
    "auth_header",
    help="Authorization header value for upstream requests",
)
@click.option(
    "--audit-log",
    type=click.Path(),
    help="Path for audit log file",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Evaluate policy but don't execute upstream calls",
)
@click.option(
    "--confirm-store",
    type=click.Path(),
    help="Path to local out-of-band confirmation store",
)
@click.option(
    "--allow-private-cidr",
    "allow_private_cidrs",
    multiple=True,
    help="Allow private CIDR targets (repeatable; default denies private ranges)",
)
@click.option(
    "--allow-redirects",
    is_flag=True,
    help="Allow redirects (each hop is re-validated against allowlists)",
)
@click.option(
    "--unsafe-no-lockfile",
    is_flag=True,
    help="Allow runtime without approved lockfile (unsafe escape hatch)",
)
@click.pass_context
def mcp_serve(
    ctx: click.Context,
    tools: str | None,
    toolpack: str | None,
    toolsets: str | None,
    toolset: str | None,
    policy: str | None,
    lockfile: str | None,
    base_url: str | None,
    auth_header: str | None,
    audit_log: str | None,
    dry_run: bool,
    confirm_store: str | None,
    allow_private_cidrs: tuple[str, ...],
    allow_redirects: bool,
    unsafe_no_lockfile: bool,
) -> None:
    """Start an MCP server exposing tools from a compiled manifest.

    The server runs on stdio transport, suitable for use with Claude Desktop
    or other MCP clients. Tools are exposed with policy enforcement,
    confirmation requirements, and audit logging.

    \b
    Examples:
      # Basic usage
      caskmcp mcp serve --tools .caskmcp/artifacts/*/tools.json

      # Resolve all paths from a toolpack
      caskmcp mcp serve --toolpack .caskmcp/toolpacks/<toolpack-id>/toolpack.yaml

      # Expose a specific curated toolset
      caskmcp mcp serve --tools tools.json --toolsets toolsets.yaml --toolset readonly

      # With policy enforcement
      caskmcp mcp serve --tools tools.json --policy policy.yaml

      # With lockfile approval enforcement
      caskmcp mcp serve --tools tools.json --lockfile caskmcp.lock.yaml

      # With upstream API configuration
      caskmcp mcp serve --tools tools.json --base-url https://api.example.com --auth "Bearer token123"

      # Dry run mode (no actual API calls)
      caskmcp mcp serve --tools tools.json --dry-run

    \b
    Claude Desktop configuration (~/.claude/claude_desktop_config.json):
      {
        "mcpServers": {
          "my-api": {
            "command": "caskmcp",
            "args": ["mcp", "serve", "--toolpack", "/path/to/toolpack.yaml"]
          }
        }
      }
    """
    resolved_confirm_store = confirm_store or str(
        confirmation_store_path(ctx.obj.get("root", resolve_root()))
    )

    from caskmcp.cli.mcp import run_mcp_serve

    lock_id = None
    if toolpack:
        lock_id = f"toolpack:{Path(toolpack).resolve()}"
    elif tools:
        lock_id = f"tools:{Path(tools).resolve()}"

    _run_with_lock(
        ctx,
        "mcp serve",
        lambda: run_mcp_serve(
            tools_path=tools,
            toolpack_path=toolpack,
            toolsets_path=toolsets,
            toolset_name=toolset,
            policy_path=policy,
            lockfile_path=lockfile,
            base_url=base_url,
            auth_header=auth_header,
            audit_log=audit_log,
            dry_run=dry_run,
            confirmation_store_path=resolved_confirm_store,
            allow_private_cidrs=list(allow_private_cidrs),
            allow_redirects=allow_redirects,
            unsafe_no_lockfile=unsafe_no_lockfile,
            verbose=ctx.obj.get("verbose", False),
        ),
        lock_id=lock_id,
    )


@mcp.command("inspect")
@click.option(
    "--artifacts", "-a",
    type=click.Path(exists=True),
    help="Path to artifacts directory",
)
@click.option(
    "--tools", "-t",
    type=click.Path(exists=True),
    help="Path to tools.json (overrides --artifacts)",
)
@click.option(
    "--policy", "-p",
    type=click.Path(exists=True),
    help="Path to policy.yaml (overrides --artifacts)",
)
@click.option(
    "--lockfile", "-l",
    type=click.Path(),
    help="Path to lockfile (default: ./caskmcp.lock.yaml)",
)
@click.pass_context
def mcp_meta(
    ctx: click.Context,  # noqa: ARG001
    artifacts: str | None,
    tools: str | None,
    policy: str | None,
    lockfile: str | None,
) -> None:
    """Start an inspect MCP server exposing read-only governance introspection.

    This server allows operators and CI tools to inspect CaskMCP capability state:
    - List and inspect available actions
    - Check if actions would be allowed by policy
    - View approval status of tools
    - Get risk summaries

    This server is read-only and does not expose approval mutation APIs.

    \b
    Examples:
      # With artifacts directory
      caskmcp mcp inspect --artifacts .caskmcp/artifacts/*/

      # With explicit paths
      caskmcp mcp inspect --tools tools.json --policy policy.yaml

    \b
    Available tools exposed:
      - caskmcp_list_actions: List all actions with filtering
      - caskmcp_check_policy: Check if action allowed by policy
      - caskmcp_get_approval_status: Get approval status
      - caskmcp_list_pending_approvals: List pending approvals
      - caskmcp_get_action_details: Get detailed action info
      - caskmcp_risk_summary: Get risk tier breakdown

    \b
    Claude Desktop configuration:
      {
        "mcpServers": {
          "caskmcp": {
            "command": "caskmcp",
            "args": ["mcp", "inspect", "--tools", "/path/to/tools.json"]
          }
        }
      }
    """
    from caskmcp.utils.deps import require_mcp_dependency

    require_mcp_dependency()

    from caskmcp.mcp.meta_server import run_meta_server

    run_meta_server(
        artifacts_dir=artifacts,
        tools_path=tools,
        policy_path=policy,
        lockfile_path=lockfile,
    )


@mcp.command("meta")
@click.option(
    "--artifacts", "-a",
    type=click.Path(exists=True),
    help="Path to artifacts directory",
)
@click.option(
    "--tools", "-t",
    type=click.Path(exists=True),
    help="Path to tools.json (overrides --artifacts)",
)
@click.option(
    "--policy", "-p",
    type=click.Path(exists=True),
    help="Path to policy.yaml (overrides --artifacts)",
)
@click.option(
    "--lockfile", "-l",
    type=click.Path(),
    help="Path to lockfile (default: ./caskmcp.lock.yaml)",
)
@click.pass_context
def mcp_meta_alias(
    ctx: click.Context,
    artifacts: str | None,
    tools: str | None,
    policy: str | None,
    lockfile: str | None,
) -> None:
    """Alias for `caskmcp mcp inspect`."""
    ctx.invoke(
        mcp_meta,
        artifacts=artifacts,
        tools=tools,
        policy=policy,
        lockfile=lockfile,
    )


@cli.group(hidden=True)
def approve() -> None:
    """Alias group for `gate` (compatibility)."""
    pass


@approve.command("sync")
@click.option(
    "--tools", "-t",
    required=True,
    type=click.Path(exists=True),
    help="Path to tools.json manifest",
)
@click.option(
    "--policy",
    type=click.Path(exists=True),
    help="Path to policy.yaml artifact (defaults to sibling of --tools if present)",
)
@click.option(
    "--toolsets",
    type=click.Path(exists=True),
    help="Path to toolsets.yaml artifact (optional)",
)
@click.option(
    "--lockfile", "-l",
    type=click.Path(),
    help="Path to lockfile (default: ./caskmcp.lock.yaml)",
)
@click.option(
    "--capture-id",
    help="Capture ID to associate with this sync",
)
@click.option(
    "--scope",
    help="Scope name to associate with this sync",
)
@click.option(
    "--deterministic/--volatile-metadata",
    default=True,
    show_default=True,
    help="Deterministic lockfile metadata by default; use --volatile-metadata for ephemeral timestamps",
)
@click.option(
    "--prune-removed/--keep-removed",
    default=False,
    show_default=True,
    help="Remove tools no longer present in the manifest from the lockfile",
)
@click.pass_context
def approve_sync(
    ctx: click.Context,
    tools: str,
    policy: str | None,
    toolsets: str | None,
    lockfile: str | None,
    capture_id: str | None,
    scope: str | None,
    deterministic: bool,
    prune_removed: bool,
) -> None:
    """Sync lockfile with a tools manifest.

    Compares the manifest against the lockfile and tracks changes:
    - New tools are added as pending approval
    - Modified tools require re-approval
    - Removed tools are tracked but not deleted

    \b
    Examples:
      caskmcp approve sync --tools tools.json
      caskmcp approve sync --tools tools.json --lockfile custom.lock.yaml
    """
    from caskmcp.cli.approve import run_approve_sync

    _run_with_lock(
        ctx,
        "approve sync",
        lambda: run_approve_sync(
            tools_path=tools,
            policy_path=policy,
            toolsets_path=toolsets,
            lockfile_path=lockfile,
            capture_id=capture_id,
            scope=scope,
            verbose=ctx.obj.get("verbose", False),
            prune_removed=prune_removed,
            deterministic=deterministic,
        ),
    )


@approve.command("list")
@click.option(
    "--lockfile", "-l",
    type=click.Path(),
    help="Path to lockfile (default: ./caskmcp.lock.yaml)",
)
@click.option(
    "--status", "-s",
    type=click.Choice(["pending", "approved", "rejected"]),
    help="Filter by approval status",
)
@click.pass_context
def approve_list(
    ctx: click.Context,
    lockfile: str | None,
    status: str | None,
) -> None:
    """List tool approvals from the lockfile.

    \b
    Examples:
      caskmcp approve list
      caskmcp approve list --status pending
      caskmcp approve list --status approved -v
    """
    from caskmcp.cli.approve import run_approve_list

    run_approve_list(
        lockfile_path=lockfile,
        status_filter=status,
        verbose=ctx.obj.get("verbose", False),
    )


@approve.command("tool")
@click.argument("tool_ids", nargs=-1)
@click.option(
    "--lockfile", "-l",
    type=click.Path(),
    help="Path to lockfile (default: ./caskmcp.lock.yaml)",
)
@click.option(
    "--all", "all_pending",
    is_flag=True,
    help="Approve all pending tools",
)
@click.option(
    "--toolset",
    help="Approve tools within a specific toolset",
)
@click.option(
    "--by",
    "approved_by",
    help="Who is approving (default: $USER)",
)
@click.option(
    "--reason",
    help="Approval reason (recorded in lockfile signature metadata)",
)
@click.pass_context
def approve_tool(
    ctx: click.Context,
    tool_ids: tuple[str, ...],
    lockfile: str | None,
    all_pending: bool,
    toolset: str | None,
    approved_by: str | None,
    reason: str | None,
) -> None:
    """Approve one or more tools.

    \b
    Examples:
      caskmcp approve tool get_users create_user
      caskmcp approve tool --all
      caskmcp approve tool get_users --by security@example.com
    """
    from caskmcp.cli.approve import run_approve_tool

    _run_with_lock(
        ctx,
        "approve tool",
        lambda: run_approve_tool(
            tool_ids=tool_ids,
            lockfile_path=lockfile,
            all_pending=all_pending,
            toolset=toolset,
            approved_by=approved_by,
            reason=reason,
            root_path=str(ctx.obj.get("root", resolve_root())),
            verbose=ctx.obj.get("verbose", False),
        ),
    )


@approve.command("reject")
@click.argument("tool_ids", nargs=-1, required=True)
@click.option(
    "--lockfile", "-l",
    type=click.Path(),
    help="Path to lockfile (default: ./caskmcp.lock.yaml)",
)
@click.option(
    "--reason", "-r",
    help="Reason for rejection",
)
@click.pass_context
def approve_reject(
    ctx: click.Context,
    tool_ids: tuple[str, ...],
    lockfile: str | None,
    reason: str | None,
) -> None:
    """Reject one or more tools.

    Rejected tools will cause CI checks to fail.

    \b
    Examples:
      caskmcp approve reject delete_all_users --reason "Too dangerous"
      caskmcp approve reject tool1 tool2
    """
    from caskmcp.cli.approve import run_approve_reject

    _run_with_lock(
        ctx,
        "approve reject",
        lambda: run_approve_reject(
            tool_ids=tool_ids,
            lockfile_path=lockfile,
            reason=reason,
            verbose=ctx.obj.get("verbose", False),
        ),
    )


@approve.command("check")
@click.option(
    "--lockfile", "-l",
    type=click.Path(),
    help="Path to lockfile (default: ./caskmcp.lock.yaml)",
)
@click.option(
    "--toolset",
    help="Check approval status for a specific toolset only",
)
@click.pass_context
def approve_check(
    ctx: click.Context,
    lockfile: str | None,
    toolset: str | None,
) -> None:
    """Check if all tools are approved (for CI).

    Exit codes:
      0 - All tools approved
      1 - Pending or rejected tools exist
      2 - No lockfile found

    \b
    Examples:
      caskmcp approve check
      caskmcp approve check --lockfile custom.lock.yaml
    """
    from caskmcp.cli.approve import run_approve_check

    run_approve_check(
        lockfile_path=lockfile,
        toolset=toolset,
        verbose=ctx.obj.get("verbose", False),
    )


@approve.command("snapshot")
@click.option(
    "--lockfile", "-l",
    type=click.Path(),
    help="Path to lockfile (default: ./caskmcp.lock.yaml)",
)
@click.pass_context
def approve_snapshot(ctx: click.Context, lockfile: str | None) -> None:
    """Materialize a baseline snapshot for an approved lockfile."""
    from caskmcp.cli.approve import run_approve_snapshot

    _run_with_lock(
        ctx,
        "approve snapshot",
        lambda: run_approve_snapshot(
            lockfile_path=lockfile,
            root_path=str(ctx.obj.get("root", resolve_root())),
            verbose=ctx.obj.get("verbose", False),
        ),
    )


@approve.command("resign")
@click.option(
    "--lockfile", "-l",
    type=click.Path(),
    help="Path to lockfile (default: ./caskmcp.lock.yaml)",
)
@click.option("--toolset", help="Re-sign approvals for tools within a specific toolset only")
@click.pass_context
def approve_resign(ctx: click.Context, lockfile: str | None, toolset: str | None) -> None:
    """Re-sign existing approval signatures (migration / repair helper)."""
    from caskmcp.cli.approve import run_approve_resign

    _run_with_lock(
        ctx,
        "approve resign",
        lambda: run_approve_resign(
            lockfile_path=lockfile,
            toolset=toolset,
            root_path=str(ctx.obj.get("root", resolve_root())),
            verbose=ctx.obj.get("verbose", False),
        ),
    )


@cli.group()
def gate() -> None:
    """Human approval workflow (canonical governance commands)."""
    pass


@gate.command("sync")
@click.option(
    "--tools", "-t",
    required=True,
    type=click.Path(exists=True),
    help="Path to tools.json manifest",
)
@click.option("--policy", type=click.Path(exists=True), help="Path to policy.yaml artifact")
@click.option("--toolsets", type=click.Path(exists=True), help="Path to toolsets.yaml artifact")
@click.option("--lockfile", "-l", type=click.Path(), help="Path to lockfile")
@click.option("--capture-id", help="Capture ID to associate with this sync")
@click.option("--scope", help="Scope name to associate with this sync")
@click.option(
    "--deterministic/--volatile-metadata",
    default=True,
    show_default=True,
    help="Deterministic lockfile metadata by default",
)
@click.option(
    "--prune-removed/--keep-removed",
    default=False,
    show_default=True,
    help="Remove tools no longer present in the manifest from the lockfile",
)
@click.pass_context
def gate_sync(
    ctx: click.Context,
    tools: str,
    policy: str | None,
    toolsets: str | None,
    lockfile: str | None,
    capture_id: str | None,
    scope: str | None,
    deterministic: bool,
    prune_removed: bool,
) -> None:
    """Alias for `caskmcp approve sync`."""
    ctx.invoke(
        approve_sync,
        tools=tools,
        policy=policy,
        toolsets=toolsets,
        lockfile=lockfile,
        capture_id=capture_id,
        scope=scope,
        deterministic=deterministic,
        prune_removed=prune_removed,
    )


@gate.command("status")
@click.option("--lockfile", "-l", type=click.Path(), help="Path to lockfile")
@click.option(
    "--status",
    "status_filter",
    type=click.Choice(["pending", "approved", "rejected"]),
    help="Filter by approval status",
)
@click.pass_context
def gate_status(
    ctx: click.Context,
    lockfile: str | None,
    status_filter: str | None,
) -> None:
    """Alias for `caskmcp approve list`."""
    ctx.invoke(approve_list, lockfile=lockfile, status=status_filter)


@gate.command("allow")
@click.argument("tool_ids", nargs=-1)
@click.option("--lockfile", "-l", type=click.Path(), help="Path to lockfile")
@click.option("--all", "all_pending", is_flag=True, help="Approve all pending tools")
@click.option("--toolset", help="Approve tools within a specific toolset")
@click.option("--by", "approved_by", help="Who is approving")
@click.option("--reason", help="Approval reason")
@click.pass_context
def gate_allow(
    ctx: click.Context,
    tool_ids: tuple[str, ...],
    lockfile: str | None,
    all_pending: bool,
    toolset: str | None,
    approved_by: str | None,
    reason: str | None,
) -> None:
    """Alias for `caskmcp approve tool`."""
    ctx.invoke(
        approve_tool,
        tool_ids=tool_ids,
        lockfile=lockfile,
        all_pending=all_pending,
        toolset=toolset,
        approved_by=approved_by,
        reason=reason,
    )


@gate.command("block")
@click.argument("tool_ids", nargs=-1, required=True)
@click.option("--lockfile", "-l", type=click.Path(), help="Path to lockfile")
@click.option("--reason", "-r", help="Reason for rejection")
@click.pass_context
def gate_block(
    ctx: click.Context,
    tool_ids: tuple[str, ...],
    lockfile: str | None,
    reason: str | None,
) -> None:
    """Alias for `caskmcp approve reject`."""
    ctx.invoke(approve_reject, tool_ids=tool_ids, lockfile=lockfile, reason=reason)


@gate.command("check")
@click.option("--lockfile", "-l", type=click.Path(), help="Path to lockfile")
@click.option("--toolset", help="Check approval status for a specific toolset")
@click.pass_context
def gate_check(
    ctx: click.Context,
    lockfile: str | None,
    toolset: str | None,
) -> None:
    """Alias for `caskmcp approve check`."""
    ctx.invoke(approve_check, lockfile=lockfile, toolset=toolset)


@gate.command("snapshot")
@click.option("--lockfile", "-l", type=click.Path(), help="Path to lockfile")
@click.pass_context
def gate_snapshot(ctx: click.Context, lockfile: str | None) -> None:
    """Alias for `caskmcp approve snapshot`."""
    ctx.invoke(approve_snapshot, lockfile=lockfile)


@gate.command("resign")
@click.option("--lockfile", "-l", type=click.Path(), help="Path to lockfile")
@click.option("--toolset", help="Re-sign approvals for tools within a specific toolset only")
@click.pass_context
def gate_resign(
    ctx: click.Context,
    lockfile: str | None,
    toolset: str | None,
) -> None:
    """Alias for `caskmcp approve resign`."""
    ctx.invoke(approve_resign, lockfile=lockfile, toolset=toolset)


@cli.group()
def scopes() -> None:
    """Scope authoring and merge workflows."""
    pass


@scopes.command("merge")
@click.option(
    "--suggested",
    type=click.Path(),
    help="Path to generated scopes.suggested.yaml (defaults to <root>/scopes/scopes.suggested.yaml)",
)
@click.option(
    "--authoritative",
    type=click.Path(),
    help="Path to authoritative scopes.yaml (defaults to <root>/scopes/scopes.yaml)",
)
@click.option(
    "--output",
    type=click.Path(),
    help="Path to write merge proposal (defaults to sibling scopes.merge.proposed.yaml)",
)
@click.option("--apply", is_flag=True, help="Apply merged proposal into authoritative scopes.yaml")
@click.pass_context
def scopes_merge(
    ctx: click.Context,
    suggested: str | None,
    authoritative: str | None,
    output: str | None,
    apply: bool,
) -> None:
    """Merge suggested scopes into authoritative scopes via explicit proposal."""
    from caskmcp.cli.scopes import run_scopes_merge

    resolved_suggested = suggested or str(_default_root_path(ctx, "scopes", "scopes.suggested.yaml"))
    resolved_authoritative = authoritative or str(_default_root_path(ctx, "scopes", "scopes.yaml"))
    def _merge_scopes() -> None:
        run_scopes_merge(
            suggested_path=resolved_suggested,
            authoritative_path=resolved_authoritative,
            output_path=output,
            apply=apply,
            verbose=ctx.obj.get("verbose", False),
        )

    if apply:
        _run_with_lock(ctx, "scopes merge", _merge_scopes)
    else:
        _merge_scopes()


@cli.group()
def confirm() -> None:
    """Out-of-band confirmation workflow for state-changing actions."""
    pass


@confirm.command("grant")
@click.argument("token_id", required=True)
@click.option(
    "--store",
    "store_path",
    type=click.Path(),
    help="Path to confirmation store",
)
@click.pass_context
def confirm_grant(ctx: click.Context, token_id: str, store_path: str | None) -> None:
    """Grant a pending confirmation token."""
    from caskmcp.cli.confirm import run_confirm_grant
    resolved_store = store_path or str(
        confirmation_store_path(ctx.obj.get("root", resolve_root()))
    )

    _run_with_lock(
        ctx,
        "confirm grant",
        lambda: run_confirm_grant(
            token_id=token_id,
            db_path=resolved_store,
            verbose=ctx.obj.get("verbose", False),
        ),
    )


@confirm.command("deny")
@click.argument("token_id", required=True)
@click.option(
    "--store",
    "store_path",
    type=click.Path(),
    help="Path to confirmation store",
)
@click.option("--reason", help="Optional denial reason")
@click.pass_context
def confirm_deny(
    ctx: click.Context,
    token_id: str,
    store_path: str | None,
    reason: str | None,
) -> None:
    """Deny a pending confirmation token."""
    from caskmcp.cli.confirm import run_confirm_deny
    resolved_store = store_path or str(
        confirmation_store_path(ctx.obj.get("root", resolve_root()))
    )

    _run_with_lock(
        ctx,
        "confirm deny",
        lambda: run_confirm_deny(
            token_id=token_id,
            db_path=resolved_store,
            reason=reason,
            verbose=ctx.obj.get("verbose", False),
        ),
    )


@confirm.command("list")
@click.option(
    "--store",
    "store_path",
    type=click.Path(),
    help="Path to confirmation store",
)
@click.pass_context
def confirm_list(ctx: click.Context, store_path: str | None) -> None:
    """List pending confirmation tokens."""
    from caskmcp.cli.confirm import run_confirm_list
    resolved_store = store_path or str(
        confirmation_store_path(ctx.obj.get("root", resolve_root()))
    )

    run_confirm_list(
        db_path=resolved_store,
        verbose=ctx.obj.get("verbose", False),
    )


@cli.command()
@click.option(
    "--toolpack",
    required=True,
    type=click.Path(exists=True),
    help="Path to toolpack.yaml",
)
@click.option(
    "--apply/--dry-run",
    "apply_changes",
    default=False,
    show_default=True,
    help="Apply migrations or print planned changes",
)
@click.pass_context
def migrate(ctx: click.Context, toolpack: str, apply_changes: bool) -> None:
    """Migrate legacy toolpack/artifact layouts to current schema contracts."""
    from caskmcp.cli.migrate import run_migrate

    _run_with_lock(
        ctx,
        "migrate",
        lambda: run_migrate(
            toolpack_path=toolpack,
            apply_changes=apply_changes,
            verbose=ctx.obj.get("verbose", False),
        ),
    )


@cli.group()
def state() -> None:
    """Local state management commands."""
    pass


@state.command("unlock")
@click.option(
    "--force",
    is_flag=True,
    help="Force remove lock even if process appears active",
)
@click.pass_context
def state_unlock(ctx: click.Context, force: bool) -> None:
    """Clear the root state lock file."""
    root = ctx.obj.get("root", resolve_root())
    try:
        clear_root_lock(root, force=force)
    except RootLockError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)
    click.echo(f"Cleared lock for root: {root}")


# Register compliance command group (lazy import)
@cli.group()
def compliance() -> None:
    """EU AI Act compliance reporting."""
    pass


@compliance.command("report")
@click.option(
    "--tools", "tools_path",
    type=click.Path(exists=True),
    help="Path to tools.json manifest",
)
@click.option(
    "--output", "output_path",
    type=click.Path(),
    default=None,
    help="Output path for the report (default: stdout as JSON)",
)
def compliance_report(tools_path: str | None, output_path: str | None) -> None:
    """Generate a structured compliance report."""
    from caskmcp.cli.compliance import run_compliance_report

    run_compliance_report(tools_path=tools_path, output_path=output_path)


@cli.command("init")
@click.option(
    "--directory", "-d",
    default=".",
    help="Project directory to initialize (default: current directory)",
)
@click.option("--non-interactive", is_flag=True, help="Use defaults without prompting")
@click.pass_context
def init_cmd(ctx: click.Context, directory: str, non_interactive: bool) -> None:
    """Initialize CaskMCP in a project directory.

    Auto-detects project type, generates config, and prints next steps.
    """
    from caskmcp.cli.init import run_init

    run_init(
        directory=directory,
        non_interactive=non_interactive,
        verbose=ctx.obj.get("verbose", False) if ctx.obj else False,
    )


@cli.group()
def propose() -> None:
    """Manage agent draft proposals for new capabilities."""
    pass


@propose.command("from-capture")
@click.argument("capture_id")
@click.option(
    "--scope",
    "-s",
    default="first_party_only",
    show_default=True,
    help="Scope to apply before generating proposals",
)
@click.option(
    "--scope-file",
    type=click.Path(exists=True),
    default=None,
    help="Optional custom scope file",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(file_okay=False),
    default=None,
    help="Directory to write proposal artifacts (defaults to <root>/proposals)",
)
@click.option(
    "--deterministic/--volatile-metadata",
    default=True,
    show_default=True,
    help="Deterministic proposal artifact IDs by default",
)
@click.pass_context
def propose_from_capture(
    ctx: click.Context,
    capture_id: str,
    scope: str,
    scope_file: str | None,
    output: str | None,
    deterministic: bool,
) -> None:
    """Generate endpoint catalog and tool proposals from a capture."""
    from caskmcp.cli.propose import run_propose_from_capture

    root = str(ctx.obj.get("root", resolve_root())) if ctx.obj else ".caskmcp"
    run_propose_from_capture(
        root=root,
        capture_id=capture_id,
        scope_name=scope,
        scope_file=scope_file,
        output_dir=output,
        deterministic=deterministic,
        verbose=ctx.obj.get("verbose", False) if ctx.obj else False,
    )


@propose.command("publish")
@click.argument("proposal_input", type=click.Path(exists=True))
@click.option(
    "--output",
    "-o",
    type=click.Path(file_okay=False),
    default=None,
    help="Directory root for published bundle output (defaults to <root>/published)",
)
@click.option(
    "--min-confidence",
    type=float,
    default=0.75,
    show_default=True,
    help="Minimum proposal confidence to include",
)
@click.option(
    "--max-risk",
    type=click.Choice(["safe", "low", "medium", "high", "critical"]),
    default="high",
    show_default=True,
    help="Maximum risk tier to include",
)
@click.option(
    "--include-review-required",
    is_flag=True,
    help="Include proposals flagged as requires_review",
)
@click.option(
    "--proposal-id",
    "proposal_ids",
    multiple=True,
    help="Restrict publish to specific proposal IDs (repeatable)",
)
@click.option(
    "--sync-lockfile",
    is_flag=True,
    help="Sync generated tools into lockfile after publish",
)
@click.option(
    "--lockfile",
    default=None,
    help="Lockfile path override (used with --sync-lockfile)",
)
@click.option(
    "--deterministic/--volatile-metadata",
    default=True,
    show_default=True,
    help="Deterministic bundle IDs and timestamps by default",
)
@click.pass_context
def propose_publish(
    ctx: click.Context,
    proposal_input: str,
    output: str | None,
    min_confidence: float,
    max_risk: str,
    include_review_required: bool,
    proposal_ids: tuple[str, ...],
    sync_lockfile: bool,
    lockfile: str | None,
    deterministic: bool,
) -> None:
    """Publish tools.proposed.yaml into runtime-ready bundle artifacts."""
    from caskmcp.cli.propose import run_propose_publish

    root = str(ctx.obj.get("root", resolve_root())) if ctx.obj else ".caskmcp"
    run_propose_publish(
        root=root,
        proposal_input=proposal_input,
        output_dir=output,
        min_confidence=min_confidence,
        max_risk=max_risk,
        include_review_required=include_review_required,
        proposal_ids=proposal_ids,
        sync_lockfile_enabled=sync_lockfile,
        lockfile_path=lockfile,
        deterministic=deterministic,
        verbose=ctx.obj.get("verbose", False) if ctx.obj else False,
    )


@propose.command("list")
@click.option("--status", type=click.Choice(["pending", "approved", "rejected"]), default=None)
@click.pass_context
def propose_list(ctx: click.Context, status: str | None) -> None:
    """List agent draft proposals."""
    from caskmcp.cli.propose import run_propose_list

    root = str(ctx.obj.get("root", resolve_root())) if ctx.obj else ".caskmcp"
    run_propose_list(root=root, status=status)


@propose.command("show")
@click.argument("proposal_id")
@click.pass_context
def propose_show(ctx: click.Context, proposal_id: str) -> None:
    """Show details of a specific proposal."""
    from caskmcp.cli.propose import run_propose_show

    root = str(ctx.obj.get("root", resolve_root())) if ctx.obj else ".caskmcp"
    run_propose_show(root=root, proposal_id=proposal_id)


@propose.command("approve")
@click.argument("proposal_id")
@click.option("--by", "reviewed_by", default="human", help="Who is approving")
@click.pass_context
def propose_approve(ctx: click.Context, proposal_id: str, reviewed_by: str) -> None:
    """Approve a proposal — marks it for future capture."""
    from caskmcp.cli.propose import run_propose_approve

    root = str(ctx.obj.get("root", resolve_root())) if ctx.obj else ".caskmcp"
    run_propose_approve(root=root, proposal_id=proposal_id, reviewed_by=reviewed_by)


@propose.command("reject")
@click.argument("proposal_id")
@click.option("--reason", "-r", default="", help="Rejection reason")
@click.option("--by", "reviewed_by", default="human", help="Who is rejecting")
@click.pass_context
def propose_reject(ctx: click.Context, proposal_id: str, reason: str, reviewed_by: str) -> None:
    """Reject a proposal with an optional reason."""
    from caskmcp.cli.propose import run_propose_reject

    root = str(ctx.obj.get("root", resolve_root())) if ctx.obj else ".caskmcp"
    run_propose_reject(root=root, proposal_id=proposal_id, reason=reason, reviewed_by=reviewed_by)


@cli.group()
def auth() -> None:
    """Manage authentication profiles for capture."""
    pass


@auth.command("login")
@click.option("--profile", required=True, help="Profile name")
@click.option("--url", required=True, help="Target URL to authenticate against")
@click.option("--root", default=None, help="CaskMCP root directory override")
@click.pass_context
def auth_login(ctx: click.Context, profile: str, url: str, root: str | None) -> None:
    """Launch headful browser for one-time login, saving storage state."""
    from caskmcp.cli.auth import auth_login as _do_login

    resolved_root = root or str(ctx.obj.get("root", resolve_root())) if ctx.obj else root or ".caskmcp"
    ctx.invoke(_do_login, profile=profile, url=url, root=resolved_root)


@auth.command("status")
@click.option("--profile", required=True, help="Profile name")
@click.option("--root", default=None, help="CaskMCP root directory override")
@click.pass_context
def auth_status(ctx: click.Context, profile: str, root: str | None) -> None:
    """Show the status of an auth profile."""
    from caskmcp.cli.auth import auth_status as _do_status

    resolved_root = root or str(ctx.obj.get("root", resolve_root())) if ctx.obj else root or ".caskmcp"
    ctx.invoke(_do_status, profile=profile, root=resolved_root)


@auth.command("clear")
@click.option("--profile", required=True, help="Profile name")
@click.option("--root", default=None, help="CaskMCP root directory override")
@click.pass_context
def auth_clear(ctx: click.Context, profile: str, root: str | None) -> None:
    """Delete an auth profile."""
    from caskmcp.cli.auth import auth_clear as _do_clear

    resolved_root = root or str(ctx.obj.get("root", resolve_root())) if ctx.obj else root or ".caskmcp"
    ctx.invoke(_do_clear, profile=profile, root=resolved_root)


@auth.command("list")
@click.option("--root", default=None, help="CaskMCP root directory override")
@click.pass_context
def auth_list_cmd(ctx: click.Context, root: str | None) -> None:
    """List all auth profiles."""
    from caskmcp.cli.auth import auth_list as _do_list

    resolved_root = root or str(ctx.obj.get("root", resolve_root())) if ctx.obj else root or ".caskmcp"
    ctx.invoke(_do_list, root=resolved_root)


def _hide_advanced_commands() -> None:
    """Hide non-flagship commands from default top-level help."""
    for name in ADVANCED_TOP_LEVEL_COMMANDS:
        command = cli.commands.get(name)
        if command is not None:
            command.hidden = True


_hide_advanced_commands()


if __name__ == "__main__":
    cli()
