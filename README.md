# CaskMCP

<!-- mcp-name: io.github.tomallicino/caskmcp -->

Compile a minimal, governed MCP tool surface from observed traffic. Like `terraform plan` for agent tools.

> **CaskMCP is a compiler for agent tool surfaces.**
> Capture real API traffic (HAR, Playwright) or import specs (OpenAPI), compile it into a minimal MCP tool surface, approve it with a lockfile, serve it, and fail CI when it drifts.

```
pip install caskmcp && caskmcp demo
```

Why this matters:
- **8,250+ MCP servers** exist and growing -- tool sprawl is the #1 agent reliability problem.
- OpenAPI is often missing, stale, or incomplete versus live behavior.
- EU AI Act (Aug 2026) requires operational evidence of what tools agents can access.
- Governance only works when the exposed tool surface is small, stable, and explicit.

## What It Is / Isn’t

**What it is**
- Mint minimal toolsets from observed behavior (HAR, Playwright) or specs (OpenAPI).
- Make the surface deterministic and diffable (stable IDs, contracts, baselines).
- Gate changes with lockfile approvals and fail CI on drift.
- Enforce policy at runtime (deny-by-default, confirm writes).

**What it is not**
- Not a generic MCP gateway or observability plane (for that, see [agentgateway](https://github.com/agentgateway/agentgateway)).
- Not just a lockfile firewall for existing MCP servers (see [MCPTrust](https://mcptrust.dev/)).
- Not another OpenAPI-to-MCP generator as an end state.

| Category | Primary job | Relationship |
| --- | --- | --- |
| CaskMCP | Tool surface compiler | Produces a minimal, governable tool surface from captures/specs |
| [FastMCP](https://gofastmcp.com/) | Server framework | Serves tools you choose to expose |
| [MintMCP](https://www.mintmcp.com/) | Enterprise gateway | Runtime auth, RBAC, audit logging; no capture or compilation |
| [MCPTrust](https://github.com/mcptrust/mcptrust) | Enforcement firewall | Runtime lockfile enforcement + signing; CaskMCP can run upstream |
| [Runlayer](https://www.runlayer.com/) | Enterprise security platform | Zero-trust MCP gateway; no traffic capture or spec compilation |
| [DriftCop](https://github.com/sudoviz/driftcop) | Static analysis + drift | Scans existing MCP servers; doesn't compile from traffic |
| [Specmatic](https://specmatic.io/) | Schema testing | Regression tests from schemas; doesn't generate specs from behavior |
| [agentgateway](https://github.com/agentgateway/agentgateway) | Enterprise proxy plane | Handles network/proxy concerns around already-exposed surfaces |

CaskMCP is the only tool that does the full loop: **observed traffic -> normalized contracts -> scoped tool surface -> approved lockfile -> MCP server -> drift gates**. Runtime proxies enforce what's already exposed; static analyzers scan existing code. CaskMCP compiles the surface from scratch.

## 5-Minute Proof (Blocking + Drift Gate)

Fastest end-to-end proof:

```bash
caskmcp demo
```

This generates a deterministic, offline demo toolpack from a bundled fixture and prints
exact next commands (`run`, `approve`, `drift`).

CI governance harness (full blocked-write + approval + drift story):

```bash
# Installs/uses local CLI and runs the full governance harness.
# The harness demonstrates:
# 1) state-changing action blocked until approval
# 2) confirmation required for writes
# 3) drift causing CI-style failure until re-approval
bash scripts/magic_moment_ci.sh
```

You should see:
- A curated readonly surface produced from capture.
- A state-changing call blocked or requiring confirmation.
- Drift check failing until lockfile re-approval.

Mint-first flow:

```bash
# 1) Mint a toolpack from real traffic (headless by default)
caskmcp mint https://app.example.com \
  -a api.example.com \
  --scope agent_safe_readonly \
  --print-mcp-config

# 2) Serve the curated surface immediately
caskmcp run --toolpack .caskmcp/toolpacks/<toolpack-id>/toolpack.yaml

# 3) CI gate: fail if surface drifts
bash scripts/magic_moment_ci.sh
```

Authenticated capture (reuse a logged-in session):

```bash
caskmcp capture record https://app.example.com \
  -a api.example.com \
  --load-storage-state auth-state.json \
  --save-storage-state auth-state.json
```

Client config snippet (Claude Desktop):

```bash
caskmcp config --toolpack /absolute/path/to/.caskmcp/toolpacks/<toolpack-id>/toolpack.yaml
```

```json
{
  "mcpServers": {
    "my-toolpack": {
      "command": "caskmcp",
      "args": [
        "run",
        "--toolpack",
        "/absolute/path/to/.caskmcp/toolpacks/<toolpack-id>/toolpack.yaml"
      ]
    }
  }
}
```

## Concepts

- **Capture**: Observed request/response traffic from HAR, Playwright, or OpenAPI import.
- **Artifact**: Deterministic compile output (`tools.json`, `toolsets.yaml`, `policy.yaml`, `baseline.json`, contracts).
- **Toolset**: Named subset of tools (for example `readonly`) used to limit what agents can call.
- **Toolpack**: Portable bundle that points to artifacts + lockfile metadata for immediate MCP serving.
- **Lockfile**: Human-approved tool surface (`pending`, `approved`, `rejected`) for runtime and CI gating.

## Use Cases

- Shrink an internal API surface for agents (start `readonly`, then expand to `operator`).
- Turn messy browser workflows into a governed, reusable toolpack.
- Gate agent tool changes in CI with drift + approvals.

## Install

```bash
pip install caskmcp
```

Optional extras:

```bash
pip install "caskmcp[playwright]"   # mint/capture
pip install "caskmcp[mcp]"          # serve
pip install "caskmcp[playwright,mcp]"  # full quickstart
pip install "caskmcp[dev]"          # contributors/CI (tests + lint + typecheck)
```

- `mcp` extra: built-in MCP server runtime
- `playwright` extra: browser traffic capture for `mint` / `capture record`
- If you installed `playwright` but not the browser binaries, run:
  `python -m playwright install chromium`
- Runtime commands that require MCP fail fast with:
  `Error: mcp not installed. Install with: pip install "caskmcp[mcp]"`

## What `mint` Produces

Default output root: `.caskmcp/`

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
  - `lockfile/caskmcp.lock.pending.yaml`
  - `evidence_summary.json` (when `--verify-ui`)
  - `evidence_summary.sha256` (when `--verify-ui`)
  - `Dockerfile`, `entrypoint.sh`, `caskmcp.run`, `requirements.lock` (when `--runtime=container`)
  - `.caskmcp/approvals/...` (after approvals, for plan/check_ci baselines)

`toolpack.yaml` is the handoff object for MCP serving (`--toolpack`).

## Permissions and Modes

CaskMCP is designed for first-party or explicitly authorized captures only. It keeps redaction on by default, applies deny-by-default policy behavior, gates state-changing operations with confirmations/approvals, and includes SSRF-oriented runtime protections (private network deny-by-default and redirect controls in proxy mode). These defaults align with [MCP security best practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices) around consent, least privilege, and explicit authorization.

## Non-goals

- Not an API reconnaissance tool.
- Not a general MITM proxy for arbitrary third-party sites.
- Not a full observability or gateway platform.

## Integrates With The Ecosystem

- List server metadata in the official [MCP Registry](https://github.com/modelcontextprotocol/registry) (follow their publishing guide; some quickstarts are npm-focused).
- Distribute/host through [Smithery](https://smithery.ai/).
- Works with platforms that support remote MCP servers, including [OpenAI tooling and connectors](https://platform.openai.com/docs/guides/tools-connectors-mcp).

## CLI Map

- `caskmcp mint` - one-shot mint loop (`capture -> compile -> toolpack`)
- `caskmcp demo` - offline fixture-backed generate-only demo path
- `caskmcp config` - emit MCP client config snippet for a toolpack
- `caskmcp doctor` - validate toolpack readiness and dependencies
- `caskmcp run` - run a toolpack locally or in a container
- `caskmcp plan` - deterministic capability diff report
- `caskmcp bundle` - deterministic zip bundle for sharing
- `caskmcp capture` - import HAR or record browser traffic
- `caskmcp openapi` - import OpenAPI spec as a capture
- `caskmcp compile` - generate artifacts/toolsets/policy/baseline
- `caskmcp approve` - sync/list/approve/reject/check lockfile status
- `caskmcp drift` - compare captures or check against baseline
- `caskmcp enforce` - runtime policy gateway (evaluate/proxy)
- `caskmcp mcp serve` - expose tools as an MCP server
- `caskmcp mcp meta` - expose governance introspection tools as MCP
- `caskmcp verify` - verify UI evidence against captured API responses *(planned)*

`caskmcp serve` is a convenience alias for `caskmcp mcp serve`.

## CI Integration

Use the built-in GitHub Action to gate PRs on drift detection:

```yaml
# .github/workflows/drift-check.yml
- uses: ./.github/actions/caskmcp-drift
  with:
    toolpack: .caskmcp/toolpacks/my-api/toolpack.yaml
```

Or use `caskmcp drift` directly in any CI system. See `examples/ci/drift-check.yml` for a full workflow.

## Demos And Docs

- `examples/mint_demo.sh` - quick mint demo
- `examples/demo.sh` - governance workflow demo
- `scripts/magic_moment_ci.sh` - unattended CI-style flow
- `docs/user-guide.md` - practical usage walkthrough
- `docs/releases/v0.1.0-alpha.4.md` - alpha release notes
- `docs/publishing.md` - PyPI + MCP Registry publishing guide

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

## License

MIT
