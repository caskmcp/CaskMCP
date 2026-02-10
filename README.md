# CaskMCP

<!-- mcp-name: io.github.caskmcp/caskmcp -->

Lockfiles for agent tools. If it's not approved, it's blocked.

CaskMCP compiles observed web traffic into governed, agent-ready tool surfaces with drift detection, Ed25519-signed approvals, and fail-closed runtime enforcement.

## The problem

Agents are remote scripts with keys. Permission prompts don't survive framework changes, team rotation, or multiple environments. Prompts aren't a control plane — diffs are.

CaskMCP moves policy into a repo artifact: a deterministic lockfile that binds what an agent can do to what was explicitly approved. No lockfile entry, no execution. Every expansion requires a signed approval. Every drift breaks CI.

## The pipeline

```
mint -> diff -> gate -> run -> drift -> verify
```

- **Mint** captures traffic (HAR or Playwright) and compiles typed tools, schemas, and a pending lockfile.
- **Diff** produces risk-classified capability diffs for code review.
- **Gate** writes Ed25519-signed approvals into an immutable lockfile.
- **Run** enforces the lockfile at runtime — unapproved tools are blocked.
- **Drift** detects changes in tool surface and fails CI on breaking changes.
- **Verify** runs assertion-based verification against post-conditions.

## Quickstart

```bash
pip install caskmcp    # Minimal install (no browser needed for demo)
cask demo              # Offline, bundled fixture, no network
```

Then try the real workflow:

```bash
# Full install (capture + MCP server)
pip install "caskmcp[playwright,mcp]"
python -m playwright install chromium

# Mint from live traffic
cask mint https://app.example.com -a api.example.com

# Review, approve, run
cask diff --toolpack .caskmcp/toolpacks/<id>/toolpack.yaml --format github-md
cask gate allow --all --lockfile .caskmcp/toolpacks/<id>/lockfile/caskmcp.lock.pending.yaml
cask run --toolpack .caskmcp/toolpacks/<id>/toolpack.yaml
```

Note: `cask` is a short alias for `caskmcp`. Both are installed by pip.

## Feature status

This table is the canonical source of truth for what's shipped vs planned.

| Feature | Status | Verified | Notes |
|---|---|---|---|
| Capture (HAR import, Playwright) | Shipped | Yes | `cask mint`, `cask capture import` — HAR parser + Playwright headless |
| Compile (tools, schemas, baseline) | Shipped | Yes | Deterministic artifacts from captured traffic |
| Diff (capability diffs) | Shipped | Yes | `cask diff --format github-md` — risk-classified |
| Gate (Ed25519 signed approvals) | Shipped | Yes | `sign_approval`, `verify_approval`, `rotate_key`, `revoke_key` all real |
| Run (fail-closed enforcement) | Shipped | Yes | Requires approved lockfile; `--unsafe-no-lockfile` escape hatch |
| Drift detection | Shipped | Yes | Exit codes 0/1/2/3; baseline vs capture comparison |
| Verify (5 modes) | Alpha | Partial | CLI wired; `core/verify/` is empty — logic lives in `cli/verify.py` only |
| Lint (governance hygiene) | Shipped | Yes | Guards, regex justification, override checks |
| Bundle (portable ZIP) | Shipped | Yes | Excludes secrets and local state |
| Compliance report (EU AI Act) | Shipped | Yes | `ComplianceReporter().generate()` returns structured evidence |
| DecisionTrace audit | Shipped | Yes | JSONL emission, thread-safe, 65 LOC |
| Network guards (SSRF, DNS) | Shipped | Yes | Scheme/private-range/redirect-hop checks in runtime |
| Container runtime | Alpha | No | Emits Dockerfile/compose; never tested at scale |
| Verification contracts | Planned | — | VerificationContract format designed, not implemented |
| Scope confidence scoring | Planned | — | ScopeDraft model exists, inference pipeline does not |
| Evidence bundles with retention | Planned | — | EvidenceBundle model designed |
| Auth / token handler BFF | Planned | — | No code exists |

## What is enforced today

- Unapproved tools cannot run (fail-closed default)
- Write/delete actions require explicit approval
- Runtime egress restricted to http/https, allowlisted hosts only
- Approval signatures are Ed25519 with signer identity
- Confirmation tokens are signed, single-use, bound to request
- DNS/IP checks block metadata and private ranges

## Threat model

Tools are code. Lockfiles are policy. Runtime is fail-closed. The control plane (`mcp inspect`) is read-only and never executes upstream actions. Agents can draft capabilities but cannot approve them. See `docs/threat-model-boundaries.md`.

## Command surface

Flagship: `mint`, `diff`, `gate`, `run`, `drift`, `verify`, `mcp serve`, `mcp inspect`

Aliases: `plan` -> `diff`, `approve` -> `gate`, `mcp meta` -> `mcp inspect`, `serve` -> `mcp serve`

Advanced (`--help-all`): `capture`, `compile`, `demo`, `config`, `scopes`, `lint`, `bundle`, `doctor`, `enforce`, `confirm`, `migrate`, `compliance`, `openapi`, `state`

## Storage and path contract

- Global `--root` defines canonical state root (default `.caskmcp`).
- `--out` is output/export convenience and does not silently redefine lookup semantics.
- Canonical locations under root:
  - `captures/<capture_id>/...`
  - `toolpacks/<toolpack_id>/toolpack.yaml`
  - `baselines/<toolpack_id>/baseline.json`
  - `state/confirmations.db`, `state/lock`, `state/keys/...`
  - `evidence/<run_id>/...`

## Documentation

- [User guide](docs/user-guide.md) — CLI workflow walkthrough
- [Architecture](ARCHITECTURE.md) — Design spec with shipped/planned status
- [Scopes](docs/scopes.md) — Scope model and ownership
- [Threat model](docs/threat-model-boundaries.md) — Trust boundaries
- [CI gate policy](docs/ci-gate-policy.md) — CI integration patterns
- [Verification spec](docs/verification-spec.md) — Verification contracts
- [Evidence redaction](docs/evidence-redaction-spec.md) — Redaction rules
- [Compatibility matrix](docs/compatibility-matrix.md) — Version compat
- [Known limitations](docs/known-limitations.md) — Current constraints
- [Playbook spec](docs/playbook-spec.md) — Playbook format
- [Publishing](docs/publishing.md) — PyPI release process

## Development

```bash
pip install -e ".[dev,packaging-test]"
python -m pytest tests/ -v
```

## License

MIT
