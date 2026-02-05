# MCPMint

**Tool foundry for AI agents: mint safe MCP toolpacks from observed traffic.**

MCPMint turns observed API behavior (HAR, Playwright, proxy captures, optional OpenAPI) into deterministic, reviewable artifacts that platform and security teams can trust in Git.

## Magic Loop: Mint

```bash
# 1) Mint a toolpack from live traffic (headless by default)
mcpmint mint https://app.example.com \
  -a api.example.com \
  --scope agent_safe_readonly \
  --print-mcp-config

# 2) Serve tools to MCP clients directly from the toolpack
mcpmint mcp serve --toolpack .mcpmint/toolpacks/<toolpack-id>/toolpack.yaml
```

`mint` captures traffic, compiles artifacts, creates a pending lockfile, and writes a first-class toolpack under `.mcpmint/toolpacks/<toolpack-id>/`.

## Governance Layer

MCPMint is **not** just “HAR -> OpenAPI -> MCP”. The wedge is:
- Curated tool surfaces with stable IDs
- Approval lockfile workflow
- Drift detection that can gate CI
- Runtime enforcement with audit logs

## 90-Second Governance Demo

```bash
# 1) Import capture
mcpmint capture import examples/sample.har \
  --allowed-hosts api.example.com \
  --name "Demo"

# 2) Compile deterministic artifacts
mcpmint compile \
  --capture <capture-id> \
  --scope first_party_only

# 3) Sync approvals (will exit 1 while tools are pending)
mcpmint approve sync \
  --tools .mcpmint/artifacts/<artifact-id>/tools.json \
  --policy .mcpmint/artifacts/<artifact-id>/policy.yaml \
  --toolsets .mcpmint/artifacts/<artifact-id>/toolsets.yaml \
  --lockfile mcpmint.lock.yaml || true

# 4) Approve for runtime use
mcpmint approve tool --all --lockfile mcpmint.lock.yaml --by security@example.com

# Optional: scoped approval gate for readonly rollout
mcpmint approve check --lockfile mcpmint.lock.yaml --toolset readonly

# 5) Enforce in proxy mode (lockfile required by default)
mcpmint enforce \
  --tools .mcpmint/artifacts/<artifact-id>/tools.json \
  --policy .mcpmint/artifacts/<artifact-id>/policy.yaml \
  --lockfile mcpmint.lock.yaml \
  --mode=proxy \
  --base-url https://api.example.com \
  --auth "Bearer $API_TOKEN"

# 5a) If a write returns confirmation_required, grant out-of-band:
mcpmint confirm grant <confirmation-token-id>

# 6) Detect drift against baseline and fail CI on risky/breaking changes
mcpmint drift \
  --baseline .mcpmint/artifacts/<artifact-id>/baseline.json \
  --capture <new-capture-id>
```

## What You Get

Compile produces reviewable artifacts in `.mcpmint/artifacts/<artifact-id>/`:

- `contract.yaml` / `contract.json`: observed API contract (OpenAPI 3.1)
- `tools.json`: curated agent tool manifest
- `toolsets.yaml`: named curated toolsets (`readonly`, `write_ops`, `high_risk`, `operator`)
- `policy.yaml`: default-deny policy with confirmation/budget rules
- `baseline.json`: drift baseline for CI checks

Approvals are tracked in:
- `mcpmint.lock.yaml`: signature-first lockfile with statuses (`pending|approved|rejected`)

## Artifact Examples

### Tool Manifest (`tools.json`)

```json
{
  "version": "1.0.0",
  "schema_version": "1.0",
  "name": "Generated Tools",
  "generated_at": "1970-01-01T00:00:00+00:00",
  "actions": [
    {
      "name": "get_user",
      "tool_id": "f4e1...",
      "endpoint_id": "a1b2c3d4e5f67890",
      "signature_id": "f4e1...",
      "method": "GET",
      "path": "/api/users/{id}",
      "host": "api.example.com",
      "risk_tier": "low",
      "confirmation_required": "never"
    }
  ]
}
```

### Approval Lockfile (`mcpmint.lock.yaml`)

```yaml
version: "1.0.0"
schema_version: "1.0"
artifacts_digest: "a2f0..."
tools:
  f4e1...:
    tool_id: f4e1...
    signature_id: f4e1...
    status: approved
    approved_by: security@example.com
    tool_version: 1
```

### Policy (`policy.yaml`)

```yaml
version: "1.0.0"
schema_version: "1.0"
default_action: deny
rules:
  - id: allow_first_party_get
    type: allow
    match:
      methods: [GET, HEAD, OPTIONS]
  - id: confirm_state_changes
    type: confirm
    match:
      methods: [POST, PUT, PATCH, DELETE]
```

## Runtime Enforcement

`mcpmint enforce` supports:
- `--mode=evaluate`: decision-only gateway
- `--mode=proxy`: decision + upstream execution
- `--toolsets` + `--toolset`: enforce a curated runtime action subset

In `proxy` mode, state-changing actions are denied unless:
- policy allows,
- out-of-band confirmation is granted (`mcpmint confirm grant <token>`), and
- lockfile approval + integrity digest checks pass.

Gateway endpoints:
- `POST /evaluate`
- `POST /execute` (proxy mode only)
- `GET /pending`
- `GET /actions`
- `GET /health`

## Metadata Mode

Deterministic output is the default to keep diffs reviewable.
Use `--volatile-metadata` only for ad-hoc local runs:

```bash
mcpmint compile --capture <capture-id> --volatile-metadata
mcpmint approve sync --tools tools.json --volatile-metadata
mcpmint drift --from <old-capture-id> --to <new-capture-id> --volatile-metadata
```

Deterministic mode stabilizes generated timestamps/IDs where supported so repeated runs over the same input produce clean diffs.

## MCP Output Target

Expose approved compiled tools to AI agents:

```bash
mcpmint mcp serve \
  --tools tools.json \
  --toolsets toolsets.yaml \
  --lockfile mcpmint.lock.yaml \
  --policy policy.yaml \
  --dry-run
```

`mcp serve` does **not** require approvals by default. Approval enforcement is enabled when `--lockfile` is provided.
If a sibling `toolsets.yaml` exists and `--toolset` is omitted, MCPMint defaults to `readonly` and prints a warning.
With toolpacks, use `mcpmint mcp serve --toolpack <toolpack.yaml>` to avoid hunting for individual artifact paths.

You can also expose governance introspection tools:

```bash
mcpmint mcp meta --tools tools.json --policy policy.yaml --lockfile mcpmint.lock.yaml
```

## Installation

```bash
pip install mcpmint
```

Requirements: Python 3.11+

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

## Documentation

- [docs/user-guide.md](docs/user-guide.md): end-to-end usage
- [SPEC.md](SPEC.md): architecture and models
- [examples/demo.sh](examples/demo.sh): scriptable walkthrough
- [examples/mint_demo.sh](examples/mint_demo.sh): one-command mint walkthrough
- [scripts/magic_moment_ci.sh](scripts/magic_moment_ci.sh): unattended CI harness for approval + confirmation + drift gate flow

## License

MIT
