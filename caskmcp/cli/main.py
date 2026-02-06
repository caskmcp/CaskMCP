"""Main CLI entry point for CaskMCP."""

import click

from caskmcp import __version__
from caskmcp.branding import (
    CLI_PRIMARY_COMMAND,
    PRODUCT_NAME,
)


@click.group()
@click.version_option(version=__version__, prog_name=CLI_PRIMARY_COMMAND)
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose output")
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    """CaskMCP: Action surface compiler for safe, agent-ready tools.

    Turn observed web traffic into contracts, tools, and policies.
    """
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["brand"] = {
        "product": PRODUCT_NAME,
        "primary_command": CLI_PRIMARY_COMMAND,
    }


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
    default=".caskmcp/captures",
    help="Output directory",
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
    output: str,
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

      # Record traffic interactively with Playwright
      caskmcp capture record https://example.com --allowed-hosts api.example.com

      # Record with pre-authenticated session
      caskmcp capture record https://example.com -a api.example.com \\
        --load-storage-state auth-state.json

    Record mode supports interactive (`--no-headless`), timed headless
    capture (`--headless --duration`), and scripted automation (`--script`).
    """
    from caskmcp.cli.capture import run_capture

    run_capture(
        subcommand=subcommand,
        source=source,
        allowed_hosts=list(allowed_hosts),
        name=name,
        output=output,
        redact=not no_redact,
        headless=headless,
        script_path=script,
        duration_seconds=duration,
        load_storage_state=load_storage_state,
        save_storage_state=save_storage_state,
        verbose=ctx.obj.get("verbose", False),
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
    default=".caskmcp",
    show_default=True,
    help="Output root directory",
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
    output: str,
    deterministic: bool,
    runtime: str,
    runtime_build: bool,
    runtime_tag: str | None,
    runtime_version_pin: str | None,
    print_mcp_config: bool,
) -> None:
    """Capture traffic and mint a first-class toolpack for MCP serving.

    \b
    Example:
      caskmcp mint https://example.com -a api.example.com --print-mcp-config
    """
    from caskmcp.cli.mint import run_mint

    run_mint(
        start_url=start_url,
        allowed_hosts=list(allowed_hosts),
        name=name,
        scope_name=scope,
        headless=headless,
        script_path=script,
        duration_seconds=duration,
        output_root=output,
        deterministic=deterministic,
        runtime_mode=runtime,
        runtime_build=runtime_build,
        runtime_tag=runtime_tag,
        runtime_version_pin=runtime_version_pin,
        print_mcp_config=print_mcp_config,
        verbose=ctx.obj.get("verbose", False),
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

    run_demo(output_root=out, verbose=ctx.obj.get("verbose", False))


@cli.command()
@click.option(
    "--toolpack",
    required=True,
    type=click.Path(exists=True),
    help="Path to toolpack.yaml",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "yaml"]),
    default="json",
    show_default=True,
    help="Output format for config snippet",
)
def config(toolpack: str, output_format: str) -> None:
    """Print a ready-to-paste MCP client config snippet."""
    from caskmcp.cli.config import run_config

    run_config(toolpack_path=toolpack, fmt=output_format)


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
    help="Path to caskmcp.lock.yaml (optional; enforces approved tools when provided)",
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
    default=".caskmcp/confirmations.db",
    show_default=True,
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
    confirm_store: str,
    allow_private_cidrs: tuple[str, ...],
    allow_redirects: bool,
) -> None:
    """Run a toolpack locally or in a container runtime."""
    from caskmcp.cli.run import run_run

    run_run(
        toolpack_path=toolpack,
        runtime=runtime,
        print_config_and_exit=print_config_and_exit,
        toolset=toolset,
        lockfile=lockfile,
        base_url=base_url,
        auth_header=auth_header,
        audit_log=audit_log,
        dry_run=dry_run,
        confirm_store=confirm_store,
        allow_private_cidrs=list(allow_private_cidrs),
        allow_redirects=allow_redirects,
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
    type=click.Choice(["json", "markdown", "both"]),
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
    """Generate a deterministic plan report."""
    from caskmcp.cli.plan import run_plan

    run_plan(
        toolpack_path=toolpack,
        baseline=baseline,
        output_dir=output,
        output_format=output_format,
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
    default=".caskmcp/captures",
    help="Output directory",
)
@click.pass_context
def openapi_import(
    ctx: click.Context,
    source: str,
    allowed_hosts: tuple[str, ...],
    name: str | None,
    output: str,
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

    run_capture_openapi(
        source=source,
        allowed_hosts=list(allowed_hosts) if allowed_hosts else None,
        name=name,
        output=output,
        verbose=ctx.obj.get("verbose", False),
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
    default=".caskmcp/artifacts",
    help="Output directory",
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
    output: str,
    deterministic: bool,
) -> None:
    """Compile captured traffic into contracts, tools, and policies.

    \b
    Examples:
      caskmcp compile --capture cap_20240204_abc123 --scope agent_safe_readonly
      caskmcp compile --capture ./captures/session.json --format manifest
    """
    from caskmcp.cli.compile import run_compile

    run_compile(
        capture_id=capture,
        scope_name=scope,
        scope_file=scope_file,
        output_format=output_format,
        output_dir=output,
        verbose=ctx.obj.get("verbose", False),
        deterministic=deterministic,
    )


@cli.command()
@click.option("--from", "from_capture", help="Source capture ID")
@click.option("--to", "to_capture", help="Target capture ID")
@click.option("--baseline", type=click.Path(exists=True), help="Baseline file path")
@click.option("--capture", "-c", "capture_id", help="Capture to compare against baseline")
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default=".caskmcp/reports",
    help="Output directory",
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
    output: str,
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

    run_drift(
        from_capture=from_capture,
        to_capture=to_capture,
        baseline=baseline,
        capture_id=capture_id,
        output_dir=output,
        output_format=output_format,
        verbose=ctx.obj.get("verbose", False),
        deterministic=deterministic,
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
    default=".caskmcp/confirmations.db",
    show_default=True,
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
    confirm_store: str,
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

    run_enforce(
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
        confirmation_store_path=confirm_store,
        allow_private_cidrs=list(allow_private_cidrs),
        allow_redirects=allow_redirects,
        unsafe_no_lockfile=unsafe_no_lockfile,
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
    help="Path to caskmcp.lock.yaml (optional; enforces approved tools when provided)",
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
    default=".caskmcp/confirmations.db",
    show_default=True,
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
    confirm_store: str,
    allow_private_cidrs: tuple[str, ...],
    allow_redirects: bool,
) -> None:
    """Alias for `caskmcp mcp serve`.

    This command exists for convenience and forwards to MCP server runtime.
    """
    click.echo(
        "Notice: `caskmcp serve` is an alias for `caskmcp mcp serve`.",
        err=True,
    )

    from caskmcp.cli.mcp import run_mcp_serve

    run_mcp_serve(
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
        confirmation_store_path=confirm_store,
        allow_private_cidrs=list(allow_private_cidrs),
        allow_redirects=allow_redirects,
        verbose=ctx.obj.get("verbose", False),
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
    help="Path to caskmcp.lock.yaml (optional; enforces approved tools when provided)",
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
    default=".caskmcp/confirmations.db",
    show_default=True,
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
    confirm_store: str,
    allow_private_cidrs: tuple[str, ...],
    allow_redirects: bool,
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
    from caskmcp.cli.mcp import run_mcp_serve

    run_mcp_serve(
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
        confirmation_store_path=confirm_store,
        allow_private_cidrs=list(allow_private_cidrs),
        allow_redirects=allow_redirects,
        verbose=ctx.obj.get("verbose", False),
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
def mcp_meta(
    ctx: click.Context,  # noqa: ARG001
    artifacts: str | None,
    tools: str | None,
    policy: str | None,
    lockfile: str | None,
) -> None:
    """Start a meta MCP server exposing CaskMCP governance tools.

    This server allows AI agents to use CaskMCP capabilities directly:
    - List and inspect available actions
    - Check if actions would be allowed by policy
    - View approval status of tools
    - Get risk summaries

    This enables agents to be governance-aware and make informed decisions.

    \b
    Examples:
      # With artifacts directory
      caskmcp mcp meta --artifacts .caskmcp/artifacts/*/

      # With explicit paths
      caskmcp mcp meta --tools tools.json --policy policy.yaml

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
            "args": ["mcp", "meta", "--tools", "/path/to/tools.json"]
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


@cli.group()
def approve() -> None:
    """Tool approval workflow for human-in-the-loop governance.

    The approval system tracks tool versions and requires explicit approval
    for new or changed tools before they can be used.
    """
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

    run_approve_sync(
        tools_path=tools,
        policy_path=policy,
        toolsets_path=toolsets,
        lockfile_path=lockfile,
        capture_id=capture_id,
        scope=scope,
        verbose=ctx.obj.get("verbose", False),
        deterministic=deterministic,
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
@click.pass_context
def approve_tool(
    ctx: click.Context,
    tool_ids: tuple[str, ...],
    lockfile: str | None,
    all_pending: bool,
    toolset: str | None,
    approved_by: str | None,
) -> None:
    """Approve one or more tools.

    \b
    Examples:
      caskmcp approve tool get_users create_user
      caskmcp approve tool --all
      caskmcp approve tool get_users --by security@example.com
    """
    from caskmcp.cli.approve import run_approve_tool

    run_approve_tool(
        tool_ids=tool_ids,
        lockfile_path=lockfile,
        all_pending=all_pending,
        toolset=toolset,
        approved_by=approved_by,
        verbose=ctx.obj.get("verbose", False),
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

    run_approve_reject(
        tool_ids=tool_ids,
        lockfile_path=lockfile,
        reason=reason,
        verbose=ctx.obj.get("verbose", False),
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

    run_approve_snapshot(
        lockfile_path=lockfile,
        verbose=ctx.obj.get("verbose", False),
    )


@cli.group()
def confirm() -> None:
    """Out-of-band confirmation workflow for state-changing actions."""
    pass


@confirm.command("grant")
@click.argument("token_id", required=True)
@click.option(
    "--store",
    "store_path",
    default=".caskmcp/confirmations.db",
    show_default=True,
    type=click.Path(),
    help="Path to confirmation store",
)
@click.pass_context
def confirm_grant(ctx: click.Context, token_id: str, store_path: str) -> None:
    """Grant a pending confirmation token."""
    from caskmcp.cli.confirm import run_confirm_grant

    run_confirm_grant(
        token_id=token_id,
        db_path=store_path,
        verbose=ctx.obj.get("verbose", False),
    )


@confirm.command("deny")
@click.argument("token_id", required=True)
@click.option(
    "--store",
    "store_path",
    default=".caskmcp/confirmations.db",
    show_default=True,
    type=click.Path(),
    help="Path to confirmation store",
)
@click.option("--reason", help="Optional denial reason")
@click.pass_context
def confirm_deny(
    ctx: click.Context,
    token_id: str,
    store_path: str,
    reason: str | None,
) -> None:
    """Deny a pending confirmation token."""
    from caskmcp.cli.confirm import run_confirm_deny

    run_confirm_deny(
        token_id=token_id,
        db_path=store_path,
        reason=reason,
        verbose=ctx.obj.get("verbose", False),
    )


@confirm.command("list")
@click.option(
    "--store",
    "store_path",
    default=".caskmcp/confirmations.db",
    show_default=True,
    type=click.Path(),
    help="Path to confirmation store",
)
@click.pass_context
def confirm_list(ctx: click.Context, store_path: str) -> None:
    """List pending confirmation tokens."""
    from caskmcp.cli.confirm import run_confirm_list

    run_confirm_list(
        db_path=store_path,
        verbose=ctx.obj.get("verbose", False),
    )


# Register compliance command group (lazy import)
@cli.group()
def compliance():
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


if __name__ == "__main__":
    cli()
