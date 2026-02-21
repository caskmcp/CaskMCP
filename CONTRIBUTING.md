# Contributing to CaskMCP

Thanks for your interest in contributing to CaskMCP.

## Code of conduct

This project follows the guidelines in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

If you experience unacceptable behavior, contact maintainers using the same private-first process documented in [SECURITY.md](SECURITY.md): request a private follow-up channel and avoid posting sensitive details publicly.

## Need help?

- Product/design questions: open a GitHub Discussion or Issue with context and expected behavior.
- Bug reports: open a GitHub Issue with repro steps and environment details.
- Security-sensitive topics: follow [SECURITY.md](SECURITY.md).

## Development setup

```bash
git clone https://github.com/caskmcp/CaskMCP.git
cd CaskMCP
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,packaging-test]"
```

For browser capture features:

```bash
pip install -e ".[all]"
python -m playwright install chromium
```

## Running tests

```bash
python -m pytest tests/ -v
```

All 730+ tests should pass in ~2 seconds. Tests must pass before submitting a PR.

## TDD policy

All behavior changes must follow TDD:

1. **RED**: Write a failing test that captures the new behavior or bug
2. **GREEN**: Write minimal code to pass the test
3. **REFACTOR**: Improve clarity and structure while keeping tests green

Do not write implementation code for behavior changes before a failing test exists and has been run.

**Exceptions** (no TDD required):
- Docs-only changes
- Formatting-only changes
- Non-behavioral refactors (pure moves/renames)
- Build/CI config changes

Even under exceptions, add regression tests if the change risks behavior, and run the full test suite after.

## Design principles

- **Safe by default**: All capture/enforcement requires explicit allowlists
- **First-party only**: Third-party requests excluded unless explicitly included
- **Redaction on**: Remove sensitive data (cookies, tokens, PII) by default
- **Audit everything**: Every compile, drift, enforce decision is logged
- **Compiler mindset**: We convert behavior into contracts, not scan for vulnerabilities
- **No bypass language**: No features that imply circumventing protections

## Code style

- Python 3.11+, PEP 8
- Format with `ruff format`
- Lint with `ruff check`
- Type check with `mypy`
- Click CLI with lazy imports for fast startup
- Pydantic models for data structures

## Architecture

See [docs/architecture.md](docs/architecture.md) for the full design spec.

Key directories:
- `caskmcp/cli/` — Click commands
- `caskmcp/core/` — Business logic
- `caskmcp/models/` — Pydantic models
- `caskmcp/mcp/` — MCP server + compat layer
- `caskmcp/utils/` — Shared helpers
- `caskmcp/storage/` — Filesystem persistence
- `tests/` — Test suite (mirrors source structure)

## Pull request process

1. Create a feature branch from `main`
2. Write tests first (TDD)
3. Implement the change
4. Run the full test suite
5. Update docs if the change affects public behavior
6. Submit a PR with a clear summary, changes list, and test plan

## Docs and release notes

- Public behavior changes must update the user-facing docs in the same PR (`README.md`, `docs/user-guide.md`, and relevant specs).
- `CHANGELOG.md` is the canonical release history. Treat `docs/releases/` as historical archive material.
- Architecture and boundary changes must update `docs/architecture.md`.

## Reporting issues

Use [GitHub Issues](https://github.com/caskmcp/CaskMCP/issues) with the provided templates for bug reports and feature requests.
