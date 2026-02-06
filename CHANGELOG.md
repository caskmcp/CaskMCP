# Changelog

All notable changes to this project will be documented in this file.

> Alpha notice: breaking changes are expected before stable `1.0.0`.

## [Unreleased]

### Added
- `caskmcp demo` command for deterministic offline first-run generation
  (fixture capture -> compile -> toolpack, generate-only).
- Packaged demo HAR fixture under `caskmcp/assets/demo/sample.har`.
- CLI tests for exact dependency error strings, compile format surface, demo behavior,
  and packaging fixture coverage.

### Changed
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

### Removed
- Removed placeholder `mcp-python` compile output format from the public CLI.
- Removed obsolete `caskmcp/cli/serve.py` dashboard stub implementation.

### Fixed
- README install matrix now matches `pyproject.toml` extras (removed stale `cryptography` extra reference).

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
