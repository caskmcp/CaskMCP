# CaskMCP User Guide

This guide documents the shipped v1 workflow and command surface.

Note: global flags like `--root` must appear before the subcommand, for example:
`cask --root .caskmcp demo`.

Canonical naming:

- `diff` is canonical (`plan` alias)
- `gate` is canonical (`approve` alias)
- `mcp inspect` is canonical (`mcp meta` alias)

## Your first 5 minutes

```bash
cask demo                                    # Offline demo from bundled fixture
cask gate allow --all --lockfile <path>      # Approve all tools
cask run --toolpack <path>                   # Run with enforcement
```

The demo runs entirely offline using a bundled HAR fixture. No Playwright or network access needed. For real capture workflows (`cask mint`), install Playwright:

```bash
pip install "caskmcp[playwright,mcp]"
python -m playwright install chromium
```

## Connect to MCP clients (Claude Desktop, Cursor, etc.)

Generate a ready-to-paste MCP client config snippet:

```bash
cask config --toolpack .caskmcp/toolpacks/<toolpack-id>/toolpack.yaml
```

Codex app config (TOML):

```bash
cask config --toolpack .caskmcp/toolpacks/<toolpack-id>/toolpack.yaml --format codex
```

Claude Desktop:

- Paste the emitted JSON into `~/Library/Application Support/Claude/claude_desktop_config.json` under `mcpServers`
- Restart Claude Desktop

macOS note: If your `caskmcp` binary or toolpack lives under `~/Documents`, `~/Desktop`, or `~/Downloads`, macOS may deny access to the spawned MCP process. If you see:
`PermissionError: [Errno 1] Operation not permitted ... pyvenv.cfg`, relocate the toolpack + install outside those folders (recommended), or grant the relevant Claude app/helper processes access.

## Day-one flow

```bash
# Optional offline proof
caskmcp demo

# Mint
caskmcp mint https://app.example.com -a api.example.com --scope agent_safe_readonly

# Diff
caskmcp diff --toolpack .caskmcp/toolpacks/<toolpack-id>/toolpack.yaml --format github-md

# Gate (once all tools are approved, this will also materialize an approved lockfile)
caskmcp gate allow --all --toolset readonly \
  --lockfile .caskmcp/toolpacks/<toolpack-id>/lockfile/caskmcp.lock.pending.yaml

# Run
caskmcp run --toolpack .caskmcp/toolpacks/<toolpack-id>/toolpack.yaml

# Drift + verify
caskmcp drift --baseline .caskmcp/toolpacks/<toolpack-id>/artifact/baseline.json --capture-id <capture-id>
caskmcp verify --toolpack .caskmcp/toolpacks/<toolpack-id>/toolpack.yaml --mode all
```

## Help surface

Default help (`caskmcp --help`) shows flagship commands only.

Full help (`caskmcp --help-all`) includes advanced commands (`capture`, `compile`, `demo`, `config`, `scopes merge`, `lint`, `bundle`, `doctor`, `enforce`, `confirm`, `migrate`, `compliance report`, etc.).

CLI aliases:

- `cask` is a full alias of `caskmcp` (same command surface).
- `plan -> diff`
- `approve -> gate`
- `mcp meta -> mcp inspect`

## Root, output, and lookup semantics

- `--root` defines canonical state root (default `.caskmcp`).
- `--out` is export/output convenience.
- Drift accepts exactly one of `--capture-id` or `--capture-path` for baseline mode.
- Relative artifact paths in toolpack metadata resolve relative to `toolpack.yaml`.

Canonical root layout:

- `captures/<capture_id>/`
- `artifacts/<artifact_id>/`
- `toolpacks/<toolpack_id>/`
- `baselines/<toolpack_id>/`
- `reports/`
- `evidence/<run_id>/`
- `state/lock`
- `state/confirmations.db`
- `state/keys/`

## Command reference

### `mint`

Captures traffic, compiles artifacts, creates toolpack, and writes pending lockfile.

### `capture` (advanced)

Low-level capture adapters for import/record workflows.

- HAR import:
  - `cask capture import traffic.har -a api.example.com`
- OTEL import:
  - `cask capture import traces.json --input-format otel -a api.example.com`
- Playwright record:
  - `cask capture record https://example.com -a api.example.com`

OTEL support is file-import only in this release (JSON/NDJSON export input).

### `diff` / `plan`

Deterministic capability diff report.

- `--format github-md` emits PR-friendly markdown.

### `gate` / `approve`

Governance workflow.

- Golden path: `gate allow --all --toolset readonly`
- Advanced: `gate sync`, `gate status`, `gate block`, `gate check`, `gate snapshot`
- `gate sync` keeps removed tools in the lockfile by default (audit-friendly). If you want to remove tools that no longer exist in the published artifacts (for example after a compiler generalization from one-off listing paths to `{slug}` templates), use `gate sync --prune-removed`.

### `run`, `mcp serve`, `serve`

Runtime execution with policy and lockfile enforcement.

- Requires approved lockfile by default.
- Pending lockfiles are rejected for runtime.
- For minted toolpacks, approvals are tracked in `lockfile/caskmcp.lock.pending.yaml`. Once all tools are approved, CaskMCP promotes an approved copy to `lockfile/caskmcp.lock.yaml` and updates `toolpack.yaml` to reference it.
- `--unsafe-no-lockfile` is explicit non-default escape hatch.
- Some hostile/anti-bot sites will return challenge pages or `403` when executed outside a real browser context. In those cases, treat runtime execution as best-effort; CaskMCP still supports capture/compile/gate, and you can still use manual browser-assisted capture/execution flows.

### `drift`

Detects changes against a baseline or between captures.

Exit codes:

- `0`: no gated drift
- `1`: gated non-breaking drift
- `2`: breaking drift
- `3`: invalid input/config

### `verify`

Verification modes:

- `contracts`, `replay`, `outcomes`, `provenance`, `all`

Provenance mode requires both:

- `--playbook <playbook.yaml|json>`
- `--ui-assertions <assertions.yaml|json>`

### `mcp inspect`

Read-only control-plane introspection for operator/CI workflows.

- No approval mutation APIs.
- No upstream execution APIs.

### `scopes merge`

Scope ownership model:

- `scopes.suggested.yaml` is generated (draft-style `drafts:` payload from compile).
- `scopes.yaml` is user-owned and authoritative.
- Merge accepts both draft-style and map-style suggestions, proposes diffs, and never silently overwrites.

### `propose from-capture`

Generates abstraction planning artifacts from a capture before lockfile publication:

- `endpoint_catalog.yaml` (templated endpoint families + parameter variability)
- `tools.proposed.yaml` (parameterized proposed tools)
- `questions.yaml` (follow-up capture prompts for low-confidence areas)

Example:

```bash
cask propose from-capture <capture-id> --scope first_party_only
```

This command is intentionally pre-approval. It curates candidate capabilities and does not modify runtime-approved lockfiles.

### `propose publish`

Promotes `tools.proposed.yaml` into runtime-ready artifacts with explicit confidence/risk filters:

- `tools.json` (action manifest)
- `toolsets.yaml` (readonly/write/operator slices)
- `policy.yaml` (default deny + budget/confirmation rules)
- `publish_report.json` (selected/excluded proposals and reasons)

Example:

```bash
cask propose publish .caskmcp/proposals/<proposal-id> \
  --min-confidence 0.70 \
  --max-risk high \
  --include-review-required
```

Optional lockfile sync from published artifacts:

```bash
cask propose publish .caskmcp/proposals/<proposal-id> \
  --sync-lockfile \
  --lockfile .caskmcp/lockfile/caskmcp.lock.pending.yaml
```

### `lint`

Fails governance hygiene issues, including:

- sensitive write/delete/money actions with empty guards
- regex usage without justification
- risk/state-changing overrides without justification

### `bundle`

Produces a portable bundle.

Bundle includes safe artifacts and excludes secrets and local sensitive state.

## Runtime safety contracts

- Approval signatures use Ed25519 signer identity.
- Trusted signer store lives at `<root>/state/keys/trusted_signers.json`.
- Local signer keypair lives at `<root>/state/keys/approval_ed25519_private.pem` and `<root>/state/keys/approval_ed25519_public.pem`.
- Rotation can keep multiple active trusted keys; revocation is explicit (`status: revoked`) and fail-closed.
- Confirmation tokens are signed and single-use.
- Runtime egress only allows `http/https`.
- Redirect hops are checked per hop.
- DNS resolution and private/metadata IP checks are enforced.
- App and IdP hosts are separated; IdP hosts are auth-only.

## Verification and provenance contracts

Defaults:

- `top_k=5`
- `min_confidence=0.70`
- `capture_window_ms=1500`
- unknown provenance budget: `20%`

Status rules:

- `pass`: threshold met and >=2 strong signals
- `unknown`: plausible candidates without threshold confidence or non-http dominance
- `fail`: no plausible candidates or assertion state not reached

## CI integration

- Use `diff --format github-md` in PR checks.
- Use gate checks via `.github/actions/caskmcp-gate/action.yml`.
- Example workflow: `.github/workflows/gate-check.yaml.example`.

## Related docs

- `docs/scopes.md`
- `docs/playbook-spec.md`
- `docs/verification-spec.md`
- `docs/evidence-redaction-spec.md`
- `docs/ci-gate-policy.md`
- `docs/compatibility-matrix.md`
- `docs/capture-otel.md`
- `docs/known-limitations.md`
- `docs/threat-model-boundaries.md`
