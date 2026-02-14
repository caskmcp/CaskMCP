# CaskMCP Examples

This folder contains runnable examples for the shipped workflow.

## Supported Happy Path (Under 5 Minutes)

The primary supported path is:

```bash
cask demo
```

The demo parses 8 API endpoints from a bundled HAR fixture, compiles them into typed tools with schemas and risk tags, and generates a pending lockfile that needs approval before runtime.

Expected output includes:

- tool count and method/path table
- artifact paths (toolpack, pending lockfile, baseline)
- next-step commands for `gate`, `run`, and `drift`

By default, `demo` writes to a temporary output root. For stable local paths, run:

```bash
cask demo --out ./demo-output
```

For the full CLI workflow walkthrough, see [docs/user-guide.md](../docs/user-guide.md).

## CI Harness (Advanced)

For unattended governance verification (approval + confirmation + drift gate):

```bash
bash scripts/magic_moment_ci.sh
```

This is an advanced validation harness, not the initial onboarding path.

Prerequisites:

- `caskmcp` available on `PATH`
- working Python runtime (`python3` or interpreter near `caskmcp`)
- `PyYAML` installed in that runtime

Optional env vars accepted by the script:

- `CASKMCP_BIN` (CLI binary override)
- `CASKMCP_PYTHON` (Python interpreter override)

## Troubleshooting

### Playwright Browser Missing

If `mint` or `capture record` fails due to missing browser binaries:

```bash
python -m playwright install chromium
```

## More Detail

For full command walkthroughs, see [docs/user-guide.md](../docs/user-guide.md).
