# Publishing CaskMCP

## PyPI

This repository includes `.github/workflows/publish-pypi.yaml` to publish from tags
using PyPI Trusted Publishing.

### One-time setup

1. Create/register the `caskmcp` project on PyPI.
2. In PyPI project settings, add a Trusted Publisher:
   - Owner: `tomallicino`
   - Repository: `CaskMCP`
   - Workflow: `publish-pypi.yaml`
   - Environment: `pypi`
3. In GitHub repo settings, create an Environment named `pypi`.

### Release

1. Bump version in:
   - `pyproject.toml`
   - `caskmcp/__init__.py`
2. Update `CHANGELOG.md`.
3. Tag and push:

```bash
git tag v0.1.0-alpha.4
git push origin v0.1.0-alpha.4
```

4. GitHub Actions builds and publishes to PyPI.

### Verify

```bash
pip install -U caskmcp
caskmcp --help
```

## Official MCP Registry

MCP Registry publishing is managed by the official publisher tooling.

Pre-reqs:
- README includes an `mcp-name` marker (already present):
  - `io.github.tomallicino/caskmcp`
- Root `server.json` is present and kept in sync with released package version.
- Repository is public.

Run:

```bash
npx -y @modelcontextprotocol/mcp-publisher@latest publish
```

Follow prompts to authenticate and submit metadata.

Notes:
- Registry metadata and packaging paths may differ by ecosystem.
- Some examples in official docs are npm-oriented; for Python packages,
  ensure metadata points to the published PyPI package and repo docs.
