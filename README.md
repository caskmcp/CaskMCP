# MCPMint

Mint a minimal, enforceable MCP tool surface from real traffic.

> **MCPMint is a compiler for agent tools.**
> It mints a minimal, stable, reviewable MCP tool surface from observed traffic (HAR, Playwright) or specs (OpenAPI), then enforces it with approvals, drift checks, and runtime policy.

Why this matters:
- Agents degrade with tool sprawl.
- OpenAPI is often missing, stale, or incomplete versus live behavior.
- Governance only works when the exposed tool surface is small, stable, and explicit.

## What It Is / Isn’t

**What it is**
- Mint tools from traffic into curated toolsets (`readonly`, `operator`, etc.).
- Produce deterministic artifacts you can diff, review, and gate in CI.
- Enforce runtime policy and approvals against a lockfile.

**What it is not**
- Not a generic MCP gateway or observability plane (for that, see [agentgateway](https://github.com/agentgateway/agentgateway)).
- Not just a lockfile firewall for existing MCP servers (see [MCPTrust](https://mcptrust.dev/)).
- Not another OpenAPI-to-MCP generator as an end state.

| Tool | Primary job | Where MCPMint fits |
| --- | --- | --- |
| [FastMCP](https://gofastmcp.com/) | Build MCP servers quickly | MCPMint mints and curates the tool surface you choose to serve |
| [MCPTrust](https://mcptrust.dev/) | Lockfile firewall for MCP servers | MCPMint generates curated toolpacks and approvals upstream of enforcement |
| [agentgateway](https://github.com/agentgateway/agentgateway) | Enterprise gateway/proxy plane | MCPMint outputs a smaller, safer surface to route through gateway infrastructure |

## 5-Minute Proof (Blocking + Drift Gate)

Fastest end-to-end proof:

```bash
# Installs/uses local CLI and runs the full governance harness.
# The harness demonstrates:
# 1) state-changing action blocked until approval
# 2) confirmation required for writes
# 3) drift causing CI-style failure until re-approval
bash scripts/magic_moment_ci.sh
```

Mint-first flow:

```bash
# 1) Mint a toolpack from real traffic (headless by default)
mcpmint mint https://app.example.com \
  -a api.example.com \
  --scope agent_safe_readonly \
  --print-mcp-config

# 2) Serve the curated surface immediately
mcpmint mcp serve --toolpack .mcpmint/toolpacks/<toolpack-id>/toolpack.yaml

# 3) CI gate: fail if surface drifts
mcpmint drift --baseline .mcpmint/toolpacks/<toolpack-id>/artifact/baseline.json --capture <new-capture-id>
```

## Concepts

- **Capture**: Observed request/response traffic from HAR, Playwright, or OpenAPI import.
- **Artifact**: Deterministic compile output (`tools.json`, `toolsets.yaml`, `policy.yaml`, `baseline.json`, contracts).
- **Toolset**: Named subset of tools (for example `readonly`) used to limit what agents can call.
- **Toolpack**: Portable bundle that points to artifacts + lockfile metadata for immediate MCP serving.
- **Lockfile**: Human-approved tool surface (`pending`, `approved`, `rejected`) for runtime and CI gating.

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

## What `mint` Produces

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

## Security Model

MCPMint is designed for first-party or explicitly authorized captures only. It keeps redaction on by default, applies deny-by-default policy behavior, gates state-changing operations with confirmations/approvals, and includes SSRF-oriented runtime protections (private network deny-by-default and redirect controls in proxy mode). These defaults align with [MCP security best practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices) around consent, least privilege, and explicit authorization.

## Integrates With The Ecosystem

- Publish servers in the [MCP Registry](https://github.com/modelcontextprotocol/registry).
- Distribute/host through [Smithery](https://smithery.ai/).
- Connect to platforms that support remote MCP servers, including [OpenAI MCP connectors](https://platform.openai.com/docs/guides/tools-connectors-mcp).

## CLI Map

- `mcpmint mint` - one-shot mint loop (`capture -> compile -> toolpack`)
- `mcpmint capture` - import HAR or record browser traffic
- `mcpmint openapi` - import OpenAPI spec as a capture
- `mcpmint compile` - generate artifacts/toolsets/policy/baseline
- `mcpmint approve` - sync/list/approve/reject/check lockfile status
- `mcpmint drift` - compare captures or check against baseline
- `mcpmint enforce` - runtime policy gateway (evaluate/proxy)
- `mcpmint mcp serve` - expose tools as an MCP server
- `mcpmint mcp meta` - expose governance introspection tools as MCP

`mcpmint serve` dashboard is currently a placeholder.

## Demos And Docs

- `examples/mint_demo.sh` - quick mint demo
- `examples/demo.sh` - governance workflow demo
- `scripts/magic_moment_ci.sh` - unattended CI-style flow
- `docs/user-guide.md` - practical usage walkthrough
- `docs/releases/v0.1.0-alpha.2.md` - alpha release notes

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

## License

MIT
