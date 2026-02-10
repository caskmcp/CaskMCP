# Changelog

All notable changes to this project will be documented in this file.

> Alpha notice: breaking changes are expected before stable `1.0.0`.

## [Unreleased]

### Added
- `docs/archive/` directory for historical reference documents.
- `ARCHITECTURE.md` with `[SHIPPED]`/`[ALPHA]`/`[PLANNED]` status markers on all sections.
- Feature Status table in README as canonical shipped/planned source of truth.
- "Your first 5 minutes" section in `docs/user-guide.md`.

### Changed
- `SPEC_VIEWPOINTS.md` renamed to `ARCHITECTURE.md`.
- `SPEC.md`, `OPENAI_VIEWPOINTS.md`, `findings.md`, `task_plan.md`, `progress.md` moved to `docs/archive/`.
- Root `user-guide.md` removed (duplicate of `docs/user-guide.md`).
- README rewritten: hero narrative, pipeline summary, quickstart, honest feature status table.
- `STRATEGY.md` and `RELEASE_PLAN.md` now reference README Feature Status table.
- `CLAUDE.md` and `AGENTS.md` updated: `SPEC.md` -> `ARCHITECTURE.md`.
- All stale `SPEC.md` and `SPEC_VIEWPOINTS.md` cross-references updated.

### Added
- `--help-all` CLI surface to expose advanced commands while keeping flagship help concise.
- `contracts.yaml` + `coverage_report.json` compile artifacts.
- `caskmcp verify` provenance schema validation for playbooks and UI assertions.
- `caskmcp migrate` for minimal artifact layout/schema migration.
- DecisionTrace JSONL audit emitter for runtime decisions.
- Root state lock command group (`caskmcp state unlock`) and mutating-command lock enforcement.
- New documentation set:
  - `docs/playbook-spec.md`
  - `docs/verification-spec.md`
  - `docs/evidence-redaction-spec.md`
  - `docs/ci-gate-policy.md`
  - `docs/compatibility-matrix.md`
  - `docs/known-limitations.md`
  - `docs/threat-model-boundaries.md`
- `caskmcp demo` command for deterministic offline first-run generation
  (fixture capture -> compile -> toolpack, generate-only).
- Packaged demo HAR fixture under `caskmcp/assets/demo/sample.har`.
- CLI tests for exact dependency error strings, compile format surface, demo behavior,
  and packaging fixture coverage.
- CI packaging smoke job that builds wheel+sdist, installs wheel in a fresh venv,
  validates both `caskmcp` and `cask` entrypoints, and runs demo+diff smoke checks.
- `packaging-test` optional dependency group for local/CI packaging fixture parity.
- Adversarial confirmation-token tests for digest/toolset/artifact binding and expiry.
- DecisionTrace stability test for one-record-per-decision and reason-code enum validation.

### Changed
- Canonical runtime lockfile fallback order now checks approved lockfile paths before legacy names.
- `mcp inspect` is strict read-only introspection (no capture/compile/drift mutation helpers).
- Runtime network safety includes explicit URL scheme checks (`http/https` only) and app/idp host split handling.
- Approval signing moved to Ed25519 with signer/key metadata recorded in lockfile approvals.
- Demo defaults to canonical `--root` output when `--out` is not provided.
- Confirmation store defaults use `<root>/state/confirmations.db`.
- **Project renamed from MCPMint to CaskMCP** to avoid brand confusion with MintMCP gateway.
  Package is now `caskmcp`, CLI is `caskmcp`, config directory is `.caskmcp/`.
- Updated competitive comparison table with MintMCP and ecosystem positioning.
- `dev` extra now includes `mcp`, `playwright`, and `build` for CI/contributor parity.
- Runtime dependency checks now fail fast with exact actionable lines for missing MCP.
- Playwright capture/mint error handling now distinguishes package missing vs browser binaries missing.
- `caskmcp doctor` now only enforces MCP dependency when `--runtime local` is explicitly requested.
- `caskmcp serve` now aliases directly to `caskmcp mcp serve`.
- Added MCP client config snippet to README.
- Added strict hatch build excludes for local caches/artifacts.
- Runtime trust-path documentation now pins default trusted signer/key locations under
  `<root>/state/keys/`.
- User docs now explicitly document `cask` as a full CLI alias of `caskmcp`.
- CLI top-level help now emphasizes canonical `gate` workflow (compat `approve` is hidden from default help).
- Top-level CLI description now uses a direct safe-by-default runtime message.

### Removed
- Removed placeholder `mcp-python` compile output format from the public CLI.
- Removed obsolete `caskmcp/cli/serve.py` dashboard stub implementation.

### Fixed
- Packaging fixture tests now avoid isolated network dependency resolution and skip when build backend is unavailable.
- Packaging fixture skip guidance now points to `caskmcp[packaging-test]`.
- README install matrix now matches `pyproject.toml` extras (removed stale `cryptography` extra reference).
- Provenance scoring no longer self-inflates by matching assertion text against itself; candidate scoring now uses action-side evidence fields only.
- Coverage precision now reports `0.0` when non-empty captures produce only generic/unclassified capability labels.

## [0.1.0-alpha.4] - 2026-02-05

### Changed
- Strengthened README positioning around first-party, authorized minting workflows.
- Added explicit use-cases, non-goals, and 5-minute proof expectations.
- Added release hygiene files at root:
  - `LICENSE`
  - `SECURITY.md`
  - `CHANGELOG.md`
- Added publishing documentation and automation:
  - `docs/publishing.md`
  - `.github/workflows/publish-pypi.yaml`

## [0.1.0-alpha.3] - 2026-02-05

### Fixed
- Resolved mypy decorator typing failures in MCP server handlers.
- Made `scripts/magic_moment_ci.sh` self-contained when `examples/sample.har`
  is not present in checkout.

## [0.1.0-alpha.2] - 2026-02-05

### Changed
- Rewrote README around the mint/tool-surface compiler wedge.
- Removed internal planning markdown files from tracked repository content.

### Fixed
- CI quality gates: lint + strict typing issues in approval/enforcement/MCP paths.

## [0.1.0-alpha.1] - 2026-02-05

### Added
- `caskmcp mint` command for capture -> compile -> toolpack orchestration.
- First-class toolpacks with pending lockfile bootstrap.
- `caskmcp mcp serve --toolpack` path resolution support.
- Headless/scripted Playwright capture support.

### Changed
- Full project rename baseline to `caskmcp` and `.caskmcp` defaults.
