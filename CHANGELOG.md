# Changelog

All notable changes to this project will be documented in this file.

> Alpha notice: breaking changes are expected before stable `1.0.0`.

## [Unreleased]

## [0.2.0-beta.6] - 2026-02-17

### Changed

- README onboarding polish for first public release:
  - Added a clear capture-path matrix (`offline fixture`, `live browser`, `existing artifacts`).
  - Reframed traffic capture as a low-friction entrypoint into governed proof, not the product headline.
- Version metadata synchronized across packaging manifests (`pyproject.toml`, `caskmcp/__init__.py`, `server.json`, `uv.lock`).

## [0.2.0-beta.5] - 2026-02-17

### Fixed

- CI portability issue in script-loader tests by resolving helper scripts from repo root instead of a parent-directory monorepo assumption.
- Packaging smoke assertion to match canonical demo headline text (`Demo complete`) emitted by the CLI.

### Changed

- Version metadata synchronized across packaging manifests (`pyproject.toml`, `caskmcp/__init__.py`, `server.json`, `uv.lock`) for first successful public PyPI release candidate.

## [0.2.0-beta.4] - 2026-02-17

### Added

- Added first-party demo fixture to repository/package artifacts:
  - `caskmcp/assets/demo/sample.har`
- Added prove orchestration helper scripts to repository root for CI parity:
  - `scripts/prove_twice_demo.py`
  - `scripts/flagship_smoke_suite.py`
- Expanded README with a dedicated traffic-capture section showing:
  - offline fixture path
  - live browser mint path
  - HAR/OTEL/OpenAPI import paths

### Fixed

- CI test failures caused by missing script/fixture files in the standalone CaskMCP repo.
- `.gitignore` now preserves the packaged demo HAR fixture while continuing to ignore arbitrary HAR captures.
- `scripts/mcp_smoke.py` lint issue (`SIM117`) by collapsing nested context managers.

## [0.2.0-beta.3] - 2026-02-17

### Added

- Unified flagship experience commands:
  - `caskmcp wow`
  - `caskmcp govern ...`
  - `caskmcp prove ...`
- Browser-optional wow flow:
  - default offline fixture path with no Playwright dependency
  - optional live path via `caskmcp wow --live`
- `prove_summary.json` machine contract with stable schema marker (`1.0.0`).
- CI workflow for live wow validation:
  - `.github/workflows/wow-live.yaml` (nightly + label-triggered PR runs).
- Docs smoke tests for onboarding and path hygiene:
  - `tests/test_docs_smoke.py`

### Changed

- Default top-level help now centers flagship groups (`wow`, `govern`, `prove`);
  legacy top-level governance verbs remain available via compatibility paths and `--help-all`.
- Packaging smoke lane now validates wheel install + offline `caskmcp wow` contract artifacts.
- Public docs now default to `caskmcp` command examples instead of `cask`.
- README install path updated for first PyPI publish (`pip install caskmcp`).
- Optional dependency layout updated:
  - added `prove` extra
  - `all` extra now focuses on runtime extras (`mcp`, `playwright`) rather than dev toolchain.

### Removed

- Repository-scaffolding docs not intended for public distribution:
  - `AGENTS.md`
  - `CLAUDE.md`

## [0.2.0-beta.2] - 2026-02-14

### Added

- OTEL capture adapter:
  - `CaptureSource.OTEL`
  - `OTELParser` for JSON/NDJSON trace-export imports
  - `cask capture import <file> --input-format otel`
- Static-asset filtering for OTEL capture imports (parity with HAR anti-noise behavior).
- Documentation for OTEL capture input: `docs/capture-otel.md`.
- `CODE_OF_CONDUCT.md` with reporting/enforcement guidelines for contributors.
- `docs/releases/README.md` to clarify release-note archive status.
- Scope merge compatibility for compile-emitted draft payloads:
  - `caskmcp scopes merge` now accepts both `scopes:` map format and `drafts:` list format.
  - Draft payloads are normalized into reviewable scope entries with risk/confidence metadata.
- Mint WebMCP augmentation:
  - `caskmcp mint --webmcp` now discovers and appends WebMCP tool exchanges before compile.
  - Added regression coverage for mint-time WebMCP session augmentation.

### Changed

- README pipeline and feature matrix now include OTEL capture input.
- README clarifies draft proposal queue vs planned autonomous draft expansion.
- CONTRIBUTING now includes code-of-conduct link, help paths, and docs/release-note contribution rules.
- ARCHITECTURE section 10 clarifies shipped proposal queue vs planned autonomous expansion.
- `docs/user-guide.md` adds OTEL capture command guidance.
- `docs/known-limitations.md` includes OTEL-specific limitations.
- `docs/publishing.md` now marks `CHANGELOG.md` as canonical release history.
- MCP/runtime: toolset-scoped runtime can use a pending lockfile when the selected toolset is fully approved (defaults to `readonly` when toolsets are present).
- `cask init` next-step guidance now uses valid command surface:
  - OpenAPI bootstrap via `caskmcp openapi <spec> -a <api-host>`
  - Runtime step via `caskmcp run --toolpack <path>`
- OpenAPI relative-server import behavior now:
  - honors explicit `--allowed-hosts` for synthetic exchange hosts,
  - defaults `session.allowed_hosts` to discovered synthetic host when unspecified,
  - emits explicit warning guidance for host override.
- README quickstart demo expectations corrected to match bundled fixture output.
- `server.json` version metadata synchronized with current package version line.
- Approval signatures now bind toolset membership and toolset approvals (`toolsets`, `approved_toolsets`, `status`) to prevent tampering. Lockfiles signed before this change must be re-approved.
- Added `caskmcp gate resign` / `caskmcp approve resign` to re-sign lockfile approvals after signature-payload changes.

### Fixed

- Lint and type-quality regressions across CLI/core/test modules (`ruff` and `mypy` now clean on the branch).
- `scopes merge` no-op behavior against compile-generated `scopes.suggested.yaml` draft payloads.

## [0.2.0-beta.1] - 2026-02-10

### Added

#### Verify Engine (`core/verify/`)
- `VerifyEngine` orchestrator with contract, replay, outcomes, and provenance modes.
- `VerificationContract` model with multi-signal assertions (equals, contains, matches_regex, gt/gte/lt/lte, exists).
- `FlakePolicy` for configurable flake tolerance in verification.
- Replay mode: offline structural comparison against saved baselines.
- Outcomes mode: evaluate contract assertions against captured data.
- Provenance mode: match UI assertions to captured API actions with confidence scoring.
- `EvidenceBundle` model with SHA-256 digests and JSONL storage.
- Evidence collection with redaction profile application.

#### Auth Profiles
- `cask auth login/status/clear/list` commands for managing capture-time auth.
- Playwright `storage_state.json` persistence with 0600 POSIX permissions.
- `--auth-profile` flag on `cask mint` for authenticated capture.
- Auth detection: auto-detects 401/403, login redirects, auth header patterns during capture.
- `TokenProvider` Protocol (design-only) for future runtime token handling.
- Auth state is excluded from toolpacks, bundles, evidence, and baselines.

#### WebMCP Capture
- `WEBMCP` capture source — discovers `navigator.modelContext` tool registrations.
- MCP-B polyfill fallback (`window.__MCP_B_TOOLS__`).
- Meta tag and `.well-known/mcp-tools.json` manifest detection.
- `--webmcp` flag on `cask mint`.

#### Agent Draft Proposals
- `MissingCapability` and `DraftProposal` models.
- `ProposalEngine` with create, list, approve, reject workflows.
- `cask propose list/show/approve/reject` CLI commands.
- Draft/published storage isolation — runtime ignores `drafts/`.

#### Project Init and MCP Config
- `cask init` command with project type auto-detection (16 language/framework rules).
- OpenAPI spec discovery during init.
- MCP client config generation for Claude Desktop, Cursor, and generic stdio.
- `.gitignore` entry generation for CaskMCP artifacts.

#### Scope Confidence Scoring
- `ScopeDraft` model with 0.0-1.0 confidence and auto `review_required` flag.
- `RiskReason` enum (STATE_CHANGING, HAS_PII, AUTH_RELATED, THIRD_PARTY, SENSITIVE_PATH).

#### Redaction Profiles
- `default_safe` profile: auth headers, tokens, keys, cookies, body patterns.
- `high_risk_pii` profile: email, phone, SSN regex patterns, aggressive body truncation.
- `get_profile()` and `list_profiles()` registry API.

#### Verify-Drift Integration
- `CONTRACT` drift type for verification contract assertion failures.
- `contract_count` field in `DriftReport`.
- Contract failures trigger exit code 2 (breaking).

### Changed
- Version bumped to `0.2.0b1` (beta).
- Development status classifier updated to `4 - Beta`.
- README feature status table updated with all beta features.
- Pipeline description expanded: `init -> mint -> diff -> gate -> run -> drift -> verify`.
- Command surface expanded with `auth` and `propose` workflow groups.

### Added (from previous unreleased)
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
- **Project renamed to CaskMCP** to avoid brand confusion with MintMCP gateway.
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
