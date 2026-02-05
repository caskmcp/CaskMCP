# MCPMint

Mint safe MCP toolpacks from observed web/API traffic.

MCPMint turns captures (Playwright, HAR, OpenAPI) into a governed MCP tool surface with:
- Deterministic artifacts you can diff in Git
- Curated toolsets (`readonly`, `operator`, etc.)
- Approval lockfiles for human-in-the-loop rollout
- Runtime enforcement + confirmation gating + drift checks

## Magic Loop (2 commands)

```bash
# 1) Capture + compile + toolpack + pending lockfile
mcpmint mint https://app.example.com \
  -a api.example.com \
  --scope agent_safe_readonly \
  --print-mcp-config

# 2) Expose the curated surface to MCP clients
mcpmint mcp serve --toolpack .mcpmint/toolpacks/<toolpack-id>/toolpack.yaml
```

That is the core wedge: agents get a safe, reviewable tool surface quickly, not raw endpoint sprawl.

## Why MCPMint

Most API→MCP workflows stop at generation. MCPMint adds change control and runtime safety:
- Stable tool identity across captures (`tool_id`, `signature_id`, versioning)
- Policy enforcement (default-deny, confirmations, budgets)
- Approval workflow (`pending/approved/rejected`) in `mcpmint.lock.yaml`
- Drift detection that can block CI on risky changes

## Install

```bash
pip install mcpmint
```

Optional extras:

```bash
pip install "mcpmint[mcp,playwright]"
```

- `mcp` extra: built-in MCP server runtime
- `playwright` extra: browser traffic capture for `mint` / `capture record`

## What `mint` produces

Default output root: `.mcpmint/`

- `captures/<capture-id>.json`
- `artifacts/<artifact-id>/`
  - `tools.json`
  - `toolsets.yaml`
  - `policy.yaml`
  - `baseline.json`
  - `contract.yaml` / `contract.json`
- `toolpacks/<toolpack-id>/`
  - `toolpack.yaml`
  - `artifact/` (copied artifacts)
  - `lockfile/mcpmint.lock.pending.yaml`

`toolpack.yaml` is the handoff object for MCP serving (`--toolpack`).

## End-to-end governance flow

```bash
# Import an existing HAR capture
mcpmint capture import examples/sample.har -a api.example.com

# Compile artifacts (deterministic by default)
mcpmint compile --capture <capture-id> --scope first_party_only

# Sync lockfile and create pending approvals
mcpmint approve sync \
  --tools .mcpmint/artifacts/<artifact-id>/tools.json \
  --policy .mcpmint/artifacts/<artifact-id>/policy.yaml \
  --toolsets .mcpmint/artifacts/<artifact-id>/toolsets.yaml \
  --lockfile mcpmint.lock.yaml

# Approve readonly surface
mcpmint approve tool --all --toolset readonly --lockfile mcpmint.lock.yaml

# Serve approved surface over MCP
mcpmint mcp serve \
  --tools .mcpmint/artifacts/<artifact-id>/tools.json \
  --toolsets .mcpmint/artifacts/<artifact-id>/toolsets.yaml \
  --toolset readonly \
  --policy .mcpmint/artifacts/<artifact-id>/policy.yaml \
  --lockfile mcpmint.lock.yaml
```

## Security defaults

- Redaction is on by default during capture
- Private network targets are blocked by default in runtime proxying
- Redirects are blocked by default
- State-changing actions require explicit confirmation when policy demands it
- Proxy mode requires lockfile unless you pass the explicit unsafe escape hatch

## CLI map

- `mcpmint mint` - one-shot magic loop (`capture -> compile -> toolpack`)
- `mcpmint capture` - import HAR or record browser traffic
- `mcpmint openapi` - import OpenAPI spec as a capture
- `mcpmint compile` - generate artifacts/toolsets/policy/baseline
- `mcpmint approve` - sync/list/approve/reject/check lockfile status
- `mcpmint drift` - compare captures or check against baseline
- `mcpmint enforce` - runtime policy gateway (evaluate/proxy)
- `mcpmint mcp serve` - expose tools as an MCP server
- `mcpmint mcp meta` - expose governance introspection tools as MCP

`mcpmint serve` dashboard is currently a placeholder.

## Demos and docs

- `examples/mint_demo.sh` - quick mint demo
- `examples/demo.sh` - governance workflow demo
- `scripts/magic_moment_ci.sh` - unattended CI-style flow
- `docs/user-guide.md` - practical usage walkthrough
- `docs/releases/v0.1.0-alpha.1.md` - alpha release notes

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

## License

MIT
