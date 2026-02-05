# Changelog

All notable changes to this project will be documented in this file.

> Alpha notice: breaking changes are expected before stable `1.0.0`.

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
- `mcpmint mint` command for capture -> compile -> toolpack orchestration.
- First-class toolpacks with pending lockfile bootstrap.
- `mcpmint mcp serve --toolpack` path resolution support.
- Headless/scripted Playwright capture support.

### Changed
- Full project rename baseline to `mcpmint` and `.mcpmint` defaults.
