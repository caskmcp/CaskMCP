# Jira Cloud Platform API Dogfood

CaskMCP self-dogfood using a curated subset of the Jira Cloud Platform REST API.

## What's committed

| File | Purpose |
|------|---------|
| `curate_spec.py` | Downloads + curates the Jira OpenAPI spec |
| `jira-api-scoped.yaml` | Curated spec (~10 paths, ~14 operations) |
| `toolpack.yaml` | Toolpack manifest |
| `artifact/` | tools.json, policy.yaml, toolsets.yaml, baseline.json |
| `lockfile/` | Pending and approved lockfiles |
| `snapshot/` | Baseline snapshot (digests.json) for CI gate check |
| `vars.env` | Reference parameters for manual runs |
| `DOGFOOD.md` | This file |

## Source spec

- **URL:** `https://developer.atlassian.com/cloud/jira/platform/swagger-v3.v3.json`
- **Version:** Rolling (`1001.0.0-SNAPSHOT`) -- no pinned git SHA
- **Pinning strategy:** SHA-256 content hash of raw downloaded bytes + HTTP metadata
- **Auth:** Basic auth (`Authorization: Basic BASE64(email:api_token)`)

## Curated endpoints

### Read-only (GET)

| Path | Methods |
|------|---------|
| `/rest/api/3/issue/{issueIdOrKey}` | GET |
| `/rest/api/3/search/jql` | GET |
| `/rest/api/3/issue/{issueIdOrKey}/comment` | GET |
| `/rest/api/3/issue/{issueIdOrKey}/comment/{id}` | GET |
| `/rest/api/3/issue/{issueIdOrKey}/transitions` | GET |
| `/rest/api/3/project` | GET |
| `/rest/api/3/project/{projectIdOrKey}` | GET |
| `/rest/api/3/users/search` | GET |
| `/rest/api/3/user` | GET |

### Write (behind confirmation)

| Path | Methods |
|------|---------|
| `/rest/api/3/issue` | POST |
| `/rest/api/3/issue/{issueIdOrKey}/comment` | POST |
| `/rest/api/3/issue/{issueIdOrKey}/transitions` | POST |

## Confirmation flow

Write endpoints require human confirmation at runtime:

```
1. AI agent calls create_issue tool
2. CaskMCP returns: confirmation required, token=cfrmv1.xxx
3. Human runs: cask confirm grant cfrmv1.xxx
4. AI agent retries with token -- request proceeds
```

## Refreshing the spec

```bash
# Re-download and re-curate
python3 dogfood/jira/curate_spec.py --refresh
```

## CI usage

**PR gate:** `.github/workflows/gate-check.yaml` runs `cask gate check`
against the committed toolpack. Triggers on PRs that modify `caskmcp/core/`,
`caskmcp/mcp/`, `caskmcp/cli/`, or `dogfood/jira/`.

**Drift check:** The Jira spec is a rolling SNAPSHOT with no pinned version.
Drift detection uses content-hash comparison via `curate_spec.py --check`,
which is suitable for scheduled/manual runs but NOT for PR gating (the
upstream spec will change between runs). No Jira token is stored in CI.
