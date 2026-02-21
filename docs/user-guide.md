# Cask User Guide

This guide covers the unified CLI experience for Cask.

## Install

```bash
pip install caskmcp
```

For source/development workflows:

```bash
pip install -e .
```

## Golden Path

```bash
cask demo
```

Required artifacts are always emitted:
- `prove_twice_report.md`
- `prove_twice_diff.json`
- `prove_summary.json`

Exit behavior:
- `0` only when governance enforcement is active and parity checks pass.
- non-zero when fail-closed enforcement or parity contract is violated.

## Optional Live/Browser Mode

```bash
pip install "caskmcp[playwright]"
python -m playwright install chromium
cask demo --live
```

## Primary Commands

### `cask init`

Initialize Cask in a project directory. Detects existing captures, OpenAPI specs, and auth configurations.

```bash
cask init
```

### `cask mint <url>`

Capture traffic from a live web app and compile a governed toolpack in one shot.

```bash
cask mint https://app.example.com -a api.example.com
```

### `cask diff`

Generate a risk-classified change report showing new tools, schema changes, and host additions.

```bash
cask diff --toolpack .caskmcp/toolpacks/<id>/toolpack.yaml
cask diff --toolpack .caskmcp/toolpacks/<id>/toolpack.yaml --format github-md
```

### `cask gate ...`

Approval workflow commands:

```bash
# Sync lockfile with tools manifest
cask gate sync --tools tools.json

# Approve all pending tools
cask gate allow --all

# Approve specific tools
cask gate allow get_users create_user

# Block a dangerous tool
cask gate block delete_all_users --reason "Too dangerous"

# Check approval status (for CI)
cask gate check

# List current approval status
cask gate status

# Materialize baseline snapshot
cask gate snapshot

# Re-sign approval signatures
cask gate reseal
```

### `cask serve`

Start the governed MCP server over stdio.

```bash
cask serve --toolpack .caskmcp/toolpacks/<id>/toolpack.yaml
```

### `cask run`

Execute a toolpack with full policy enforcement.

```bash
cask run --toolpack .caskmcp/toolpacks/<id>/toolpack.yaml
```

### `cask drift`

Detect capability surface changes between a baseline and current state.

```bash
cask drift --baseline .caskmcp/toolpacks/<id>/artifact/baseline.json --capture-id <id>
```

### `cask verify`

Run assertion-based verification contracts.

```bash
cask verify --toolpack .caskmcp/toolpacks/<id>/toolpack.yaml
```

### `cask demo`

Run the full governance proof loop offline in ~30 seconds.

```bash
# Default: offline fixture-based proof
cask demo

# With live browser capture
cask demo --live

# Smoke matrix
cask demo --smoke
```

## Traffic Capture

### Import existing files

```bash
# HAR files
cask capture import traffic.har -a api.example.com

# OpenTelemetry traces
cask capture import traces.json --input-format otel -a api.example.com

# OpenAPI specs (auto-detected)
cask capture import openapi.yaml -a api.example.com
```

### Live browser recording

```bash
cask capture record https://app.example.com -a api.example.com
```

## Verification Workflows

Cask integrates a workflow runner for structured verification:

```bash
# Initialize a workflow
cask workflow init

# Run a workflow
cask workflow run workflow.yaml

# Compare two runs
cask workflow diff run_a/ run_b/

# Generate a report
cask workflow report run_dir/

# Check workflow dependencies
cask workflow doctor
```

## Help Surface

- `cask --help` shows the core command surface.
- `cask --help-all` shows all commands including advanced ones.

## MCP Client Config

Generate config snippets for AI clients:

```bash
# JSON (Claude Desktop, Cursor)
cask config --toolpack .caskmcp/toolpacks/<id>/toolpack.yaml

# Codex TOML
cask config --toolpack .caskmcp/toolpacks/<id>/toolpack.yaml --format codex
```

## Safety Model

- Fail-closed lockfile enforcement by default
- Ed25519 signed approvals in lockfile
- Runtime egress safety (scheme, DNS/IP, redirect-hop checks)
- Drift checks for capability surface changes
- Audit logs for governance decisions (DecisionTrace)
- Export boundary excluding auth state, signing keys, and raw secrets

## Known Limitations

See [Known Limitations](known-limitations.md) for runtime and capture caveats.
