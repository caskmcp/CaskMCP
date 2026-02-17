# CaskMCP

<!-- mcp-name: io.github.caskmcp/caskmcp -->

CaskMCP is a governed MCP capability supply chain with replayable proof.

Core contract:
- `caskmcp wow` proves governance enforcement, replayability, and parity in one run.
- `caskmcp govern ...` is the governance surface (approvals, lockfiles, drift gates, runtime policy).
- `caskmcp prove ...` is the proof surface (prove-twice and smoke matrix).

## Install

```bash
pip install caskmcp
```

For local development:

```bash
git clone https://github.com/caskmcp/CaskMCP.git
cd CaskMCP/cask
pip install -e .
```

## Zero-Friction Wow

Default wow path is offline and browser-free:

```bash
caskmcp wow
```

Artifacts emitted on every run:
- `prove_twice_report.md`
- `prove_twice_diff.json`
- `prove_summary.json`

`caskmcp wow` exits `0` only when all are true:
1. Governance was enforced in fail-closed mode.
2. Run A and Run B replay deterministically from the same governed inputs.
3. Parity passed.

### Optional Live Browser Path

```bash
pip install "caskmcp[playwright]"
python -m playwright install chromium
caskmcp wow --live
```

## Primary CLI Shape

```bash
caskmcp wow
caskmcp govern --help
caskmcp prove --help
```

Examples:

```bash
# Governed capture -> compile
caskmcp govern mint https://app.example.com -a api.example.com

# Review and approve pending lockfile
caskmcp govern diff --toolpack .caskmcp/toolpacks/<id>/toolpack.yaml --format github-md
caskmcp govern gate allow --all --lockfile .caskmcp/toolpacks/<id>/lockfile/caskmcp.lock.pending.yaml

# Enforced runtime + drift checks
caskmcp govern run --toolpack .caskmcp/toolpacks/<id>/toolpack.yaml
caskmcp govern drift --baseline .caskmcp/toolpacks/<id>/artifact/baseline.json --capture-id <capture-id>

# Prove matrix
caskmcp prove smoke
```

`cask` remains an alias for compatibility, but docs/defaults use `caskmcp`.

## Why This Exists

MCP adoption is accelerating, while official guidance highlights tool-injection and trust risks in third-party MCP servers.

- OpenAI MCP risk framing and safety guidance: [OpenAI MCP docs](https://platform.openai.com/docs/mcp)
- Remote MCP allowlist pressure: [xAI remote MCP tools](https://docs.x.ai/docs/guides/tools/remote-mcp-tools)
- Registry moderation is intentionally permissive: [MCP moderation policy](https://modelcontextprotocol.io/registry/moderation-policy)
- Real incident context: [Asana MCP data exposure write-up](https://www.upguard.com/blog/asana-discloses-data-exposure-bug-in-mcp-server)

CaskMCP focuses on local governance and evidence, not bypass tooling.

## Packaging

- Distribution: `caskmcp`
- Base install: supports offline `wow`
- Extra: `playwright` (live/browser capture)
- Extra: `mcp` (MCP SDK integration)
- Extra: `all` (convenience install for `mcp` + `playwright`)

## Development

```bash
pip install -e ".[dev,packaging-test]"
pytest tests/ -v
ruff check caskmcp tests
mypy caskmcp --ignore-missing-imports
```

## Docs

- [Architecture](ARCHITECTURE.md)
- [User Guide](docs/user-guide.md)
- [Known Limitations](docs/known-limitations.md)
- [Publishing](docs/publishing.md)
