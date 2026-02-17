# CaskMCP User Guide

This guide reflects the unified external experience:
- one product: `caskmcp`
- one default wow command: `caskmcp wow`
- two primary surfaces: `govern` and `prove`

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
caskmcp wow
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
caskmcp wow --live
```

## Primary Commands

### `caskmcp govern ...`

Governance/runtime commands:
- `mint`
- `diff`
- `gate`
- `run`
- `drift`
- `verify`
- `mcp`

Examples:

```bash
caskmcp govern mint https://app.example.com -a api.example.com
caskmcp govern diff --toolpack .caskmcp/toolpacks/<id>/toolpack.yaml --format github-md
caskmcp govern gate allow --all --lockfile .caskmcp/toolpacks/<id>/lockfile/caskmcp.lock.pending.yaml
caskmcp govern run --toolpack .caskmcp/toolpacks/<id>/toolpack.yaml
```

### `caskmcp prove ...`

Proof commands:
- `twice`
- `smoke`

Examples:

```bash
caskmcp prove twice
caskmcp prove smoke
```

### `caskmcp wow`

Happy-path alias for the prove-twice contract.

## Help Surface

- `caskmcp --help` shows the flagship surface (`wow`, `govern`, `prove`).
- `caskmcp --help-all` shows advanced/compatibility commands.

`cask` remains a compatibility alias, but defaults and docs use `caskmcp`.

## MCP Client Config

Generate client config snippet:

```bash
caskmcp config --toolpack .caskmcp/toolpacks/<id>/toolpack.yaml
```

## Safety Model (Current)

- Fail-closed lockfile enforcement by default
- Signed approvals in lockfile
- Drift checks for capability surface changes
- Audit logs for governance decisions

## Known Limitations

See [Known Limitations](known-limitations.md) for runtime and capture caveats.
