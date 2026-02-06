# MCPMint User Guide

This guide covers the governance workflow end-to-end:
1. Capture observed API behavior
2. Compile deterministic artifacts
3. Approve tools through lockfile
4. Enforce policy + approvals at runtime
5. Detect drift and gate CI

## Fast Path: Mint Toolpack

For the one-command loop (capture -> compile -> MCP-ready toolpack):

```bash
mcpmint mint https://app.example.com \
  -a api.example.com \
  --scope agent_safe_readonly \
  --print-mcp-config
```

Outputs:

```text
.mcpmint/toolpacks/<toolpack-id>/
├── toolpack.yaml
├── artifact/
│   ├── tools.json
│   ├── toolsets.yaml
│   ├── policy.yaml
│   └── baseline.json
└── lockfile/
    └── mcpmint.lock.pending.yaml
```

Serve directly:

```bash
mcpmint run --toolpack .mcpmint/toolpacks/<toolpack-id>/toolpack.yaml
```

Generate a client config snippet:

```bash
mcpmint config --toolpack .mcpmint/toolpacks/<toolpack-id>/toolpack.yaml
```

Sanity check the toolpack before running:

```bash
mcpmint doctor --toolpack .mcpmint/toolpacks/<toolpack-id>/toolpack.yaml --runtime local
```

Optional container runtime (emits Dockerfile + entrypoint + run wrapper):

```bash
mcpmint mint https://app.example.com \
  -a api.example.com \
  --scope agent_safe_readonly \
  --runtime=container

mcpmint run --toolpack .mcpmint/toolpacks/<toolpack-id>/toolpack.yaml --runtime container
```

## Install

```bash
pip install mcpmint
mcpmint --version
```

If you installed `playwright` but not the browser binaries, run:
`python -m playwright install chromium`

## 1) Capture Traffic

### Import HAR

```bash
mcpmint capture import recording.har \
  --allowed-hosts api.example.com \
  --name "My API Session"
```

### Record with Playwright

```bash
pip install 'mcpmint[playwright]'
playwright install chromium

mcpmint capture record https://app.example.com \
  --allowed-hosts api.example.com \
  --headless \
  --duration 30
```

Scripted capture is also supported:

```bash
mcpmint capture record https://app.example.com \
  --allowed-hosts api.example.com \
  --script scripts/capture_flow.py
```

`scripts/capture_flow.py` must export:

```python
async def run(page, context) -> None:
    ...
```

### Playbook Capture (Deterministic)

```bash
mcpmint capture record https://app.example.com \
  --allowed-hosts api.example.com \
  --playbook flows/search.yaml \
  --headless
```

Minimal playbook example:

```yaml
version: "1.0"
steps:
  - id: open
    type: goto
    url: "https://app.example.com"
  - id: search
    type: type
    selector: "input[name='q']"
    text: "test"
  - id: submit
    type: press
    selector: "input[name='q']"
    key: "Enter"
```

### Import OpenAPI (bootstrap)

```bash
mcpmint openapi openapi.yaml --name "Bootstrap Session"
```

## 2) Compile Artifacts

```bash
mcpmint compile \
  --capture <capture-id> \
  --scope first_party_only \
  --format all
```

Outputs:

```text
.mcpmint/artifacts/<artifact-id>/
├── contract.yaml
├── contract.json
├── tools.json
├── toolsets.yaml
├── policy.yaml
└── baseline.json
```

Notes:
- Deterministic metadata is the default for review-friendly Git diffs.
- Artifacts include `schema_version` for compatibility checks.

### Tool manifest shape

`tools.json` actions use top-level endpoint fields:

```json
{
  "schema_version": "1.0",
  "actions": [
    {
      "name": "get_user",
      "signature_id": "abc123...",
      "endpoint_id": "def456...",
      "method": "GET",
      "path": "/api/users/{id}",
      "host": "api.example.com",
      "input_schema": {"type": "object", "properties": {"id": {"type": "string"}}}
    }
  ]
}
```

## 3) Approval Workflow (Lockfile)

Sync manifest into lockfile (new/changed tools become pending):

```bash
mcpmint approve sync \
  --tools .mcpmint/artifacts/<artifact-id>/tools.json \
  --policy .mcpmint/artifacts/<artifact-id>/policy.yaml \
  --toolsets .mcpmint/artifacts/<artifact-id>/toolsets.yaml \
  --lockfile mcpmint.lock.yaml || true
```

Review and approve:

```bash
mcpmint approve list --lockfile mcpmint.lock.yaml
mcpmint approve tool --all --lockfile mcpmint.lock.yaml --by security@example.com
mcpmint approve check --lockfile mcpmint.lock.yaml

# Optional: scoped governance for a rollout toolset
mcpmint approve check --lockfile mcpmint.lock.yaml --toolset readonly
```

Important behavior:
- Lockfile identity is signature-first (`signature_id`) for stability.
- Name-based lookups still work for operator UX.
- Lockfile stores an `artifacts_digest` over `tools.json` + `toolsets.yaml` + `policy.yaml`.
- Approvals materialize a baseline snapshot under `.mcpmint/approvals/...` inside the toolpack.

If you need to backfill a snapshot (rare), run:

```bash
mcpmint approve snapshot --lockfile mcpmint.lock.yaml
```

## 3.5) Plan + Bundle

Generate a deterministic capability diff (defaults to the approved snapshot baseline):

```bash
mcpmint plan --toolpack .mcpmint/toolpacks/<toolpack-id>/toolpack.yaml
```

Use `--baseline` to compare against another snapshot/toolpack if needed.

Bundle a toolpack for sharing (toolpack + plan + config + RUN.md):

```bash
mcpmint bundle \
  --toolpack .mcpmint/toolpacks/<toolpack-id>/toolpack.yaml \
  --out ./toolpack_bundle.zip
```

## 4) Runtime Enforcement Gateway

### Evaluate mode (policy decision only)

```bash
mcpmint enforce \
  --tools .mcpmint/artifacts/<artifact-id>/tools.json \
  --toolsets .mcpmint/artifacts/<artifact-id>/toolsets.yaml \
  --toolset readonly \
  --policy .mcpmint/artifacts/<artifact-id>/policy.yaml \
  --mode=evaluate
```

### Proxy mode (decision + upstream execution)

```bash
mcpmint enforce \
  --tools .mcpmint/artifacts/<artifact-id>/tools.json \
  --policy .mcpmint/artifacts/<artifact-id>/policy.yaml \
  --lockfile mcpmint.lock.yaml \
  --mode=proxy \
  --base-url https://api.example.com \
  --auth "Bearer $API_TOKEN"
```

In `proxy` mode, `--lockfile` is required by default so runtime always enforces approvals and artifact-digest integrity.
Use `--unsafe-no-lockfile` only as an explicit local escape hatch.
State-changing calls require out-of-band confirmation by default:

```bash
mcpmint confirm list
mcpmint confirm grant <confirmation_token_id>
```

## 5) Verification

Verify that UI actions map cleanly to captured API responses:

```bash
mcpmint verify https://app.example.com \
  --allowed-hosts api.example.com \
  --playbook flows/search.yaml
```

Mint + verify in one command:

```bash
mcpmint mint https://app.example.com \
  -a api.example.com \
  --playbook flows/search.yaml \
  --verify-ui
```

Gateway endpoints:
- `GET /health`
- `GET /actions`
- `GET /policy`
- `GET /pending`
- `POST /evaluate`
- `POST /execute`

Example evaluate call:

```bash
curl -X POST http://localhost:8081/evaluate \
  -H "Content-Type: application/json" \
  -d '{"action":"get_user","params":{"id":"123"}}'
```

## 5) Drift Detection + CI Gate

Compare two captures:

```bash
mcpmint drift --from <old-capture-id> --to <new-capture-id>
mcpmint drift --from <old-capture-id> --to <new-capture-id> --volatile-metadata
```

Compare against baseline:

```bash
mcpmint drift \
  --baseline .mcpmint/artifacts/<artifact-id>/baseline.json \
  --capture <new-capture-id>
```

Exit codes:
- `0`: no risky drift
- `1`: warning-level drift (review)
- `2`: breaking/critical drift (fail CI)

CI example:

```bash
mcpmint drift --baseline baseline.json --capture "$CAPTURE_ID"
STATUS=$?
if [ "$STATUS" -eq 2 ]; then
  echo "Breaking drift detected"
  exit 1
fi
```

## 6) MCP Integration

Serve compiled tools to MCP clients:

```bash
mcpmint mcp serve \
  --tools tools.json \
  --toolsets toolsets.yaml \
  --lockfile mcpmint.lock.yaml \
  --policy policy.yaml \
  --dry-run
```

Or resolve all paths from a minted toolpack:

```bash
mcpmint mcp serve --toolpack .mcpmint/toolpacks/<toolpack-id>/toolpack.yaml
```

Approval behavior:
- default (no `--lockfile`): no approval gate, only toolset/policy constraints apply
- with `--lockfile`: only approved tools are exposed
- if `toolsets.yaml` exists and `--toolset` is omitted: defaults to `readonly` with a warning

Serve governance/meta tools:

```bash
mcpmint mcp meta --tools tools.json --policy policy.yaml --lockfile mcpmint.lock.yaml
```

## 7) Scope Reference

Built-in scopes:
- `first_party_only`
- `auth_surface`
- `state_changing`
- `pii_surface`
- `agent_safe_readonly`

Examples:

```bash
mcpmint compile --capture <capture-id> --scope auth_surface
mcpmint compile --capture <capture-id> --scope agent_safe_readonly
```

## 8) Documentation Maintenance Rule

When behavior changes, update docs in the same change:
- `README.md` (positioning + key workflow)
- `docs/user-guide.md` (command-level behavior)
- `examples/demo.sh` (if workflow steps changed)

Minimum doc checks before merge:
- All CLI examples run against current command flags.
- Artifact snippets match actual JSON/YAML shape.
- Runtime/CI claims match enforced behavior.

## 9) Optional Volatile Metadata Mode

Use volatile metadata only when you explicitly want ephemeral IDs/timestamps:

```bash
mcpmint compile --capture <capture-id> --volatile-metadata
mcpmint approve sync --tools tools.json --volatile-metadata
mcpmint drift --from <old-capture-id> --to <new-capture-id> --volatile-metadata
```

## 10) CI Magic-Moment Harness

Run the end-to-end governance demo in CI (compile -> blocked write -> lockfile approval -> out-of-band grant -> allowed retry -> drift gate -> re-approval):

```bash
bash scripts/magic_moment_ci.sh
```

The repository CI workflow runs this harness as the `magic-moment` job.
