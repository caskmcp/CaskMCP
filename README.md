[![PyPI](https://img.shields.io/pypi/v/caskmcp)](https://pypi.org/project/caskmcp/)
[![Python 3.11+](https://img.shields.io/pypi/pyversions/caskmcp)](https://pypi.org/project/caskmcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/caskmcp/CaskMCP/actions/workflows/ci.yaml/badge.svg)](https://github.com/caskmcp/CaskMCP/actions/workflows/ci.yaml)

# Cask — Governed AI agent tools from real API traffic

<!-- mcp-name: io.github.caskmcp/cask -->

Turn any web API into a governed, agent-ready MCP server. Lockfile-based approval. Fail-closed by default. Audit everything.

<!-- hero-start -->
<p align="center">
  <img src="docs/assets/hero-comparison.gif" alt="Without Cask vs With Cask — side-by-side comparison" width="100%">
</p>
<!-- hero-end -->

## The Problem

AI agents need tools. MCP gives them tools. But **who governs what those tools can do?**

MCP adoption is accelerating while trust and safety remain unsolved. [OpenAI warns about tool-injection risks](https://platform.openai.com/docs/mcp). [Real incidents are already happening](https://www.upguard.com/blog/asana-discloses-data-exposure-bug-in-mcp-server). Cask provides the missing governance layer: local, deterministic, auditable, fail-closed.

## See It Work (30 seconds)

```bash
pip install caskmcp
cask demo
```

What just happened:
- Compiled a governed toolpack from offline fixtures
- Enforced fail-closed lockfile governance (no lockfile = no runtime)
- Proved deterministic replay parity between two independent runs
- Emitted `prove_summary.json`, `prove_twice_report.md`, and `prove_twice_diff.json`

Exit code `0` means governance held, parity passed, and everything is deterministic.

<p align="center">
  <img src="docs/assets/cask-demo.gif" alt="cask demo — governance proof in 30 seconds" width="80%">
</p>

## Quick Start (5 minutes)

**Prerequisites:** Python 3.11+

```bash
# 1. Initialize cask in your project
cask init

# 2. Capture traffic and compile a governed toolpack
cask mint https://your-app.com -a api.your-app.com

# 3. Review what changed (risk-classified diff)
cask diff --toolpack .caskmcp/toolpacks/*/toolpack.yaml

# 4. Approve tools for use
cask gate allow --all

# 5. Start the governed MCP server
cask serve --toolpack .caskmcp/toolpacks/*/toolpack.yaml
```

Your AI agent now has governed, auditable access to your API.

## How It Works

```
  Capture ─── Compile ─── Review ─── Approve ─── Serve ─── Verify
    │            │           │          │           │          │
  HAR/OTEL    tools.json   cask diff  lockfile   MCP stdio  contracts
  OpenAPI     policy.yaml            signatures              drift
  Browser     contracts                                      evidence
```

**Capture** real traffic (HAR, OpenTelemetry, OpenAPI specs, or live browser sessions).
**Compile** into deterministic, versioned tool definitions with risk classification.
**Review** changes with `cask diff` -- every new tool, schema change, or host addition is risk-classified.
**Approve** via signed lockfile entries -- explicit human decisions, not silent defaults.
**Serve** through MCP with fail-closed enforcement -- unapproved tools never execute.
**Verify** with assertion-based contracts, drift detection, and evidence bundles for CI.

## Why Cask?

**Safe by default.** Fail-closed lockfile enforcement means unapproved tools never run. No lockfile, no runtime. Period.

**Auditable.** Every approval is signed. Every runtime decision produces a trace. Every verification run creates an evidence bundle.

**Deterministic.** Same inputs produce identical artifacts and digests. Replay parity is a first-class contract, not an aspiration.

**Zero friction.** `cask demo` proves the entire governance loop offline in 30 seconds. `cask mint` captures and compiles in one command. OpenAPI specs are auto-detected on import.

**CI-native.** `cask gate check` gates deployments. `cask drift` catches API surface changes. `cask verify` runs assertion-based contracts. All exit codes are machine-readable.

## Traffic Capture

Start where you already are:

| You have | Command | Best for |
| --- | --- | --- |
| Nothing (just exploring) | `cask demo` | Fastest first run, no credentials needed |
| A web app to capture | `cask mint https://app.example.com -a api.example.com` | Capturing real authorized behavior |
| HAR/OTEL files | `cask capture import traffic.har -a api.example.com` | Adopting Cask without recapturing |
| An OpenAPI spec | `cask capture import openapi.yaml -a api.example.com` | Generating tools from specs |

All paths converge to the same governed runtime.

## Core Commands

| Command | What it does |
| --- | --- |
| `cask init` | Initialize Cask in your project |
| `cask mint <url>` | Capture traffic and compile a toolpack |
| `cask diff` | Generate a risk-classified change report |
| `cask gate allow` | Approve tools for use |
| `cask gate check` | CI gate: exit 0 only if all tools approved |
| `cask serve` | Start the governed MCP server (stdio) |
| `cask run` | Execute a toolpack with policy enforcement |
| `cask drift` | Detect capability surface changes |
| `cask verify` | Run verification contracts |
| `cask config` | Generate MCP client config snippet |
| `cask demo` | Prove governance works (offline, 30 seconds) |

> **Tip:** Both `cask` and `caskmcp` work as the CLI entry point. `cask` is preferred.

Run `cask --help` for the full command tree, or `cask --help-all` for advanced commands.

## Installation

**Prerequisites:** Python 3.11+

```bash
# Base install (includes offline demo)
pip install caskmcp

# With MCP server support
pip install "caskmcp[mcp]"

# With live browser capture
pip install "caskmcp[playwright]"
python -m playwright install chromium

# Everything
pip install "caskmcp[all]"
```

## MCP Client Config

Generate a config snippet for your AI client:

```bash
# For Claude Desktop
cask config --toolpack .caskmcp/toolpacks/*/toolpack.yaml --format json

# For Codex
cask config --toolpack .caskmcp/toolpacks/*/toolpack.yaml --format codex
```

Or add this to your Claude Desktop config (`~/.claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "my-api": {
      "command": "cask",
      "args": ["serve", "--toolpack", "/path/to/toolpack.yaml"]
    }
  }
}
```

## Documentation

- [User Guide](docs/user-guide.md) — full command reference and workflows
- [Architecture](docs/architecture.md) — system design and component specs
- [Glossary](docs/glossary.md) — key terms and concepts
- [Troubleshooting](docs/troubleshooting.md) — common issues and fixes
- [Known Limitations](docs/known-limitations.md) — runtime and capture caveats
- [Publishing](docs/publishing.md) — PyPI release process

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, TDD policy, and pull request process.

```bash
git clone https://github.com/caskmcp/CaskMCP.git
cd CaskMCP/cask
pip install -e ".[dev,packaging-test]"
pytest tests/ -v
```

## License

[MIT](LICENSE)
