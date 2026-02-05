# MCPMint Findings

## Research Log

### 2025-02-04: Project Positioning Analysis

**Source**: User feedback document "Project Summary: MCPMint"

**Key Insights**:

1. **Core Problem Statement**:
   - Gap A: "Docs lie" - specs drift from production
   - Gap B: "Tool surfaces are unsafe" - agents need guardrails
   - Gap C: "Change is silent" - breaking changes appear as runtime drift

2. **Target Users (Priority Order)**:
   - Platform / DevEx teams (primary)
   - AI agent builders and AI platform teams (primary)
   - AppSec / security engineering (secondary buyer)

3. **Differentiator**:
   - Not "API discovery" - it's a **compiler**
   - Input: Traffic + policies
   - Output: Safe, versioned action surface + enforceable guardrails

4. **The Hook**:
   > "Turn a messy web app into safe agent tools in under 5 minutes."

### Components to Port from API Scout

| Component | Status | Notes |
|-----------|--------|-------|
| HAR parser | To port | `api_scout/core/har_parser.py` |
| Endpoint normalizer | To port | Path templating, clustering |
| Auth flow detection | To port | Reframe as "Auth Surface Scope" |
| Request/Response models | To port | Pydantic models |

### Components to Build Fresh

| Component | Priority | Notes |
|-----------|----------|-------|
| Scope Engine | P0 | Elevate Focus Mode concept |
| Contract Compiler | P0 | OpenAPI generation |
| Tool Manifest | P0 | Agent-callable actions |
| Drift Engine | P1 | Diff and classification |
| Policy Engine | P1 | Enforcement rules |
| Enforcer | P2 | Runtime gate |

### Non-Negotiable Defaults (from spec)

1. **Allowlist required** - Any capture/enforcement requires explicit allowed hosts
2. **First-party only by default** - Third-party excluded unless explicitly included
3. **Redaction on by default** - Remove cookies, auth headers, token patterns
4. **State-changing requires confirmation** - POST/PUT/PATCH/DELETE need human confirm
5. **Audit logging always on** - Every decision is logged
6. **No "bypass" language** - Nothing that implies circumventing protections

### Scopes DSL Design (Draft)

```yaml
# scope: first_party_only
name: first_party_only
description: Include only requests to configured first-party domains
filters:
  - type: host_allowlist
    hosts: ["${FIRST_PARTY_DOMAINS}"]
  - type: exclude_patterns
    patterns:
      - "*.google-analytics.com"
      - "*.doubleclick.net"
      - "*.facebook.com"
      - "cdn.*"
risk_classification:
  default: low
redaction:
  level: standard
```

### Tool Manifest Schema (Draft)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "name": { "type": "string" },
    "description": { "type": "string" },
    "endpoint_id": { "type": "string" },
    "method": { "type": "string" },
    "path_template": { "type": "string" },
    "input_schema": { "$ref": "#/$defs/jsonSchema" },
    "output_schema": { "$ref": "#/$defs/jsonSchema" },
    "risk_tier": { "enum": ["safe", "read", "write", "destructive"] },
    "requires_confirmation": { "type": "boolean" },
    "rate_limit": {
      "type": "object",
      "properties": {
        "calls_per_minute": { "type": "integer" },
        "max_payload_bytes": { "type": "integer" }
      }
    },
    "allowed_hosts": { "type": "array", "items": { "type": "string" } }
  }
}
```

### Drift Report Schema (Draft)

```json
{
  "from": "capture_id or baseline",
  "to": "capture_id",
  "generated_at": "ISO timestamp",
  "summary": {
    "breaking": 0,
    "auth": 0,
    "risk": 0,
    "additive": 0,
    "unknown": 0
  },
  "changes": [
    {
      "type": "breaking|auth|risk|additive|unknown",
      "endpoint_id": "hash",
      "description": "Response schema changed: field 'user.email' removed",
      "severity": "high|medium|low",
      "details": {}
    }
  ],
  "ci_exit_code": 1
}
```
