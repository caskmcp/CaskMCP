# CaskMCP

<!-- mcp-name: io.github.caskmcp/caskmcp -->

**Your agent is not a coworker. It's a remote script with keys.**

Permission prompts don't survive framework changes, team rotation, or multiple environments. "Always allow" toggles become permanent, invisible escalation paths — outside review, outside CI, outside audit.

Prompts are not a control plane. Lockfiles are.

CaskMCP compiles observed web traffic into governed, agent-ready tool surfaces. Every tool requires explicit approval. Every expansion requires a signed authorization. Every drift breaks CI. No lockfile entry, no execution.

## 2-minute quickstart

```bash
pip install caskmcp
cask demo
```

This runs offline with bundled fixture data — no network, no browser, no keys. You'll see:
- 8 tools compiled from captured API traffic
- Risk tiers assigned (safe/low/medium/high/critical)
- A pending lockfile waiting for human approval
- MCP integration instructions for connecting to any AI agent

## The pipeline

```
init → mint → diff → gate → run → drift → verify
```

| Stage | What it does |
|-------|-------------|
| **init** | Detect project type, bootstrap `.caskmcp/` config |
| **mint** | Capture traffic (Playwright/HAR/OpenAPI/OTEL/WebMCP) → compile typed tools → generate pending lockfile |
| **diff** | Produce risk-classified capability diffs for code review |
| **gate** | Write Ed25519-signed approvals into an immutable lockfile |
| **run** | Enforce lockfile at runtime — unapproved tools blocked |
| **drift** | Detect tool surface changes, fail CI on breaking changes |
| **verify** | Run contract assertions, replay checks, outcome verification |

## What this is not

- Not a bot framework or orchestration runtime.
- Not a self-approval loop; agents can draft suggestions but cannot grant privileges.
- Not an anti-bot bypass tool; capture is for first-party, authorized surfaces only.
- Not a promise that hostile/anti-bot sites will execute outside a real browser context; runtime is best-effort on those surfaces, but capture/compile/gate still works.

## Full workflow

```bash
# Install with browser capture + MCP server
pip install "caskmcp[playwright,mcp]"
python -m playwright install chromium

# Initialize your project
cask init

# Mint from live traffic
cask mint https://app.example.com -a api.example.com

# Import OTEL traces (file export) into the same capture pipeline
cask capture import traces.json --input-format otel -a api.example.com

# Mint with auth (one-time login, reusable profile)
cask auth login --profile myapp --url https://app.example.com
cask mint https://app.example.com -a api.example.com --auth-profile myapp

# Mint with aggressive PII redaction
cask mint https://app.example.com -a api.example.com --redaction-profile high_risk_pii

# Review and approve
cask diff --toolpack .caskmcp/toolpacks/<id>/toolpack.yaml --format github-md
cask gate allow --all --lockfile .caskmcp/toolpacks/<id>/lockfile/caskmcp.lock.pending.yaml

# Optional lockfile hygiene: remove tools that no longer exist in the published artifact
cask gate sync --prune-removed \
  --tools .caskmcp/toolpacks/<id>/artifact/tools.json \
  --policy .caskmcp/toolpacks/<id>/artifact/policy.yaml \
  --toolsets .caskmcp/toolpacks/<id>/artifact/toolsets.yaml \
  --lockfile .caskmcp/toolpacks/<id>/lockfile/caskmcp.lock.pending.yaml

# Run under enforcement
cask run --toolpack .caskmcp/toolpacks/<id>/toolpack.yaml

# Check for drift
cask drift --baseline .caskmcp/toolpacks/<id>/artifact/baseline.json \
  --capture-path .caskmcp/captures/<cap-id>

# Verify contracts
cask verify --toolpack .caskmcp/toolpacks/<id>/toolpack.yaml
```

Note: `cask` is a short alias for `caskmcp`. Both installed by pip.

## Connect to your AI agent

Generate a ready-to-paste MCP client config snippet:

```bash
cask config --toolpack .caskmcp/toolpacks/<id>/toolpack.yaml
# or:
cask run --toolpack .caskmcp/toolpacks/<id>/toolpack.yaml --print-config-and-exit
```

Default output is JSON. For the Codex app config (TOML), use:

```bash
cask config --toolpack .caskmcp/toolpacks/<id>/toolpack.yaml --format codex
```

JSON output looks like:

```json
{
  "mcpServers": {
    "<id>": {
      "command": "/absolute/path/to/caskmcp",
      "args": [
        "--root",
        "/absolute/path/to/.caskmcp",
        "mcp",
        "serve",
        "--toolpack",
        "/absolute/path/to/toolpack.yaml"
      ]
    }
  }
}
```

Claude Desktop:

- Paste the emitted JSON into `~/Library/Application Support/Claude/claude_desktop_config.json` under `mcpServers`
- Restart Claude Desktop

Claude Code CLI:

```bash
claude mcp add <id> -- /absolute/path/to/caskmcp --root /absolute/path/to/.caskmcp mcp serve --toolpack /absolute/path/to/toolpack.yaml
```

macOS note: If you point Claude Desktop at paths under `~/Documents`, `~/Desktop`, or `~/Downloads`, macOS may deny access and you may see:
`PermissionError: [Errno 1] Operation not permitted ... pyvenv.cfg`. Fix by relocating the toolpack + `caskmcp` install outside those folders (recommended), or by granting the relevant Claude app/helper processes access to those folders.

## What is enforced today

- **Fail-closed default**: Unapproved tools cannot execute
- **Ed25519 signed approvals**: Signer identity + timestamp in lockfile
- **Confirmation tokens**: State-changing actions and high/critical-risk tools require explicit out-of-band confirmation
- **Network safety**: Egress restricted to http/https, allowlisted hosts only
- **DNS/IP guards**: Metadata and private range requests blocked
- **Confirmation tokens**: Signed, single-use, bound to specific request
- **Audit trail**: Every decision logged (JSONL, thread-safe)

## Intelligence features

Beyond enforcement, CaskMCP automatically:

- **Infers schemas** from observed request/response JSON
- **Detects API flows** (parent → child endpoint dependencies via field matching)
- **Auto-tags endpoints** (commerce, auth, users, search — from path/field/HTTP signals)
- **Normalizes paths** (`/products/123` → `/products/{id}`, and repeated slug variants collapse to templates like `{slug}`)
- **Resolves ephemeral routing tokens** for frameworks like Next.js (`/_next/data/{buildId}/...`) so tools stay usable across deploys
- **Splits GraphQL tools by operation** when `operationName` is observed (otherwise falls back to a generic GraphQL tool)
- **Classifies GraphQL query operations into read-only toolsets** using captured query text and persisted-query operation-name heuristics
- **Scores scope confidence** (0.0–1.0 with risk reasons, auto-flags for review)
- **Classifies risk tiers** (safe/low/medium/high/critical per endpoint)
- **Generates dependency hints** in tool descriptions ("Call get_products first to obtain product_id")

## EU AI Act readiness

The EU AI Act becomes fully applicable August 2, 2026. CaskMCP's lockfile approach directly maps to key requirements:

| Requirement | CaskMCP evidence |
|---|---|
| Human oversight | Ed25519-signed approval chain (who approved what, when) |
| Risk management | Tools classified by risk tier, high-risk flagged for review |
| Accuracy monitoring | Drift detection with breaking-change CI gates |
| Audit trail | JSONL decision trace for every tool invocation |
| Tool inventory | Complete manifest of accessible tools by risk tier |

Generate a structured compliance report:

```bash
cask compliance report --tools .caskmcp/toolpacks/<id>/artifact/tools.json
```

## Feature status

| Feature | Status | Wired | Notes |
|---|---|---|---|
| Capture (HAR, Playwright, OpenAPI, OTEL) | Shipped | Yes | OTEL supports file imports (`--input-format otel`) |
| Compile (tools, schemas, baseline) | Shipped | Yes | Deterministic artifacts from captured traffic |
| Scope filtering (5 presets) | Shipped | Yes | first_party_only, auth_surface, state_changing, pii_surface, agent_safe_readonly |
| Redaction (headers/params/body) | Shipped | Yes | Built-in patterns + profile support |
| Auto-tagging (domain/HTTP/field) | Shipped | Yes | commerce, users, auth, admin, search, content |
| Path normalization | Shipped | Yes | Dynamic segments → `{param}` |
| Flow detection | Shipped | Yes | Detects endpoint dependencies via field matching |
| Diff (capability diffs) | Shipped | Yes | `cask diff --format github-md` — risk-classified |
| Gate (Ed25519 signed approvals) | Shipped | Yes | Sign, verify, rotate, revoke all functional |
| Run (fail-closed enforcement) | Shipped | Yes | Requires approved lockfile |
| Drift detection | Shipped | Yes | Exit codes 0/1/2/3; baseline vs capture |
| Scope inference | Shipped | Yes | `scopes.suggested.yaml` emitted during compile |
| Redaction profiles | Shipped | Yes | `--redaction-profile high_risk_pii` on mint |
| Compliance reporting | Shipped | Yes | `cask compliance report` — EU AI Act evidence |
| Agent draft proposals (draft queue + from-capture generator/publisher) | Shipped | Yes | `cask propose from-capture|publish|list|show|approve|reject`; autonomous draft expansion remains planned |
| WebMCP capture | Beta | Yes | `cask mint --webmcp` — discovers navigator.modelContext |
| Verify engine | Beta | Yes | Contracts, replay, outcomes, provenance |
| Evidence bundles | Beta | Partial | JSONL bundles with SHA-256 digests |
| Auth profiles | Beta | Yes | `cask auth login/status/clear/list` |
| Auth detection | Beta | Yes | Auto-detects 401/403, auth headers during capture |
| Project init | Beta | Yes | `cask init` — auto-detects project type |
| Lint (governance hygiene) | Shipped | Yes | Guards, regex justification, override checks |
| Bundle (portable ZIP) | Shipped | Yes | Excludes secrets and local state |
| Network guards (SSRF, DNS) | Shipped | Yes | Scheme/private-range/redirect-hop checks |
| Container runtime | Alpha | No | Emits Dockerfile/compose; untested at scale |
| Runtime token handler BFF | Planned | — | `TokenProvider` Protocol defined, adapters not implemented |

## Command surface

**Flagship**: `init`, `mint`, `diff`, `gate`, `run`, `drift`, `verify`, `mcp serve`, `mcp inspect`

**Workflows**: `auth` (login/status/clear/list), `propose` (from-capture/publish/list/show/approve/reject), `compliance` (report)

**Aliases**: `plan` → `diff`, `approve` → `gate`, `mcp meta` → `mcp inspect`, `serve` → `mcp serve`

**Advanced** (`--help-all`): `capture`, `compile`, `demo`, `config`, `scopes`, `lint`, `bundle`, `doctor`, `enforce`, `confirm`, `migrate`, `openapi`, `state`

## Documentation

- [Architecture](ARCHITECTURE.md) — Design spec with shipped/planned status
- [Scopes](docs/scopes.md) — Scope model and ownership
- [Threat model](docs/threat-model-boundaries.md) — Trust boundaries
- [CI gate policy](docs/ci-gate-policy.md) — CI integration patterns
- [Verification spec](docs/verification-spec.md) — Verification contracts
- [Evidence redaction](docs/evidence-redaction-spec.md) — Redaction rules
- [OTEL capture](docs/capture-otel.md) — OTEL import format and mapping
- [Known limitations](docs/known-limitations.md) — Current constraints
- [Publishing](docs/publishing.md) — PyPI release process

## Development

```bash
git clone https://github.com/caskmcp/CaskMCP.git
cd CaskMCP
pip install -e ".[dev,packaging-test]"
python -m pytest tests/ -v    # 730+ tests, ~2s
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, TDD policy, and design principles.

## License

MIT
