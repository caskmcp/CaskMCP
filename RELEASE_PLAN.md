# MCPMint Release Plan (Option B: Ship the Real Wedge)

Based on external review feedback. Goal: ship a working end-to-end path that delivers the magic moment.

## Current State (What's Solid)

- HAR import → normalized endpoints with stable IDs
- Scopes (first_party, auth_surface, state_changing, pii_surface, agent_safe_readonly)
- Policy generation (deny-by-default, allow GET, confirm writes, budgets)
- Drift detection and reporting
- Enforcement engine (evaluates decisions, doesn't execute)
- 129 tests, full type checking, clean lint

## The Gap

The docs promise "capture → compile → run a safe MCP server" but:
1. `mcpmint serve` is not implemented
2. `compile` outputs manifests, not a runnable MCP server
3. Enforcer evaluates but doesn't forward/execute requests
4. No approval lockfile for persistent version/approval tracking

## Release Checklist (Priority Order)

### P0: Magic Moment (Must Have)

- [x] **1. MCP Server Output** - `mcpmint mcp serve`
  - ~~Generate a runnable MCP server from compiled artifacts~~
  - ~~Option A: Generate Python code using mcp-python SDK~~
  - ~~Option B: Generate config for openapi-mcp-generator~~
  - **Implemented Option C: Built-in MCP server that reads tools.json**
  - Features: policy enforcement, dry-run mode, auth support, audit logging
  - 9 tests, full type checking

- [x] **2. Proxy/Execute Mode** - `mcpmint enforce --mode=proxy`
  - Evaluate mode: policy decisions only (default)
  - Proxy mode: evaluate → execute upstream → audit → return
  - Makes governance *real*, not advisory
  - Full HTTP forwarding with auth support

- [x] **3. Approval Lockfile** - `mcpmint.lock.yaml`
  ```yaml
  version: "1.0.0"
  generated_at: "2026-02-04T..."
  tools:
    get_users:
      tool_id: "get_users"
      tool_version: 1
      signature_id: "782c682d156b76a9"
      endpoint_id: "c26a3074d074aa53"
      approved_at: "2026-02-04T..."
      approved_by: "tom@example.com"
      risk_tier: "low"
    create_user:
      tool_id: "create_user"
      tool_version: 1
      signature_id: "5ebc278450cbefb2"
      approved_at: null  # Pending approval
      risk_tier: "high"
  ```
  - `mcpmint approve <tool_id>` to approve pending tools
  - Drift proposes changes, requires explicit accept
  - CI fails on unapproved tools

- [x] **4. 60-Second Demo Script**
  - Export HAR from browser
  - `mcpmint capture import demo.har --allowed-hosts api.example.com`
  - `mcpmint compile --scope first_party_only --output mcp`
  - `mcpmint serve --port 3000`
  - Claude/agent calls a GET → works
  - Claude/agent calls a POST → blocked/requires confirmation
  - Drift detection when API changes

### P1: Polish (Should Have)

- [x] **5. Honest README Rewrite**
  - What works today (with actual commands)
  - What's planned (roadmap)
  - One real demo that runs end-to-end

- [x] **6. Record Mode** - `mcpmint capture record`
  - Use Playwright to capture traffic interactively
  - Launches browser, records API traffic, filters by host
  - Press Ctrl+C to stop recording

- [x] **7. MCP Tool for Agents**
  - Expose MCPMint itself as an MCP tool
  - Agents can: list actions, evaluate policy, check drift
  - Meta: use MCPMint to govern MCPMint-generated tools

### P2: Nice to Have

- [ ] **8. Chrome Extension** (already in plan)
- [ ] **9. Dashboard UI** - `mcpmint serve` with web UI
- [x] **10. OpenAPI import** - `mcpmint openapi`
  - Import OpenAPI 3.0/3.1 specs as capture sessions
  - Bootstrap tools from existing API documentation

## Implementation Order

```
Week 1: P0 items 1-3 (MCP output + proxy mode + lockfile)
Week 2: P0 item 4 + P1 item 5 (demo + README)
Week 3: Polish + soft launch
```

## Differentiation (What Makes This Worth It)

The moat is NOT "HAR → OpenAPI" (commoditized). The moat IS:

1. **Safe-by-default curation** - Scopes reduce blast radius
2. **Stable tool identity** - tool_id/signature_id/versioning/aliases
3. **Drift gating** - Breaks builds when action surface changes unsafely
4. **Runtime enforcement** - Governance is real, not advisory
5. **Approval workflow** - Human-in-the-loop for risky tools

## Competitors to Watch

- [har-to-openapi](https://github.com/jonluca/har-to-openapi) - HAR → OpenAPI (commodity)
- [openapi-mcp-generator](https://github.com/harsha-iiiv/openapi-mcp-generator) - OpenAPI → MCP (commodity)
- [agentgateway.dev](https://agentgateway.dev/) - Agent gateway/governance (direct competitor)
- [Optic](https://apisyouwonthate.com/blog/turn-http-traffic-into-openapi-with-optic/) - Traffic → OpenAPI with diff

## Target Users

1. **Platform/security teams** - Need policy + audit + approval around agent tools
2. **AI engineers** - Bootstrap tools from undocumented APIs, curate safe surface
3. **API teams** - Spec from truth (traffic) with governance on top

## Success Metrics

- [ ] 60-second demo works end-to-end
- [ ] First external user runs it successfully
- [ ] HN/Twitter launch with positive reception
- [ ] First GitHub star from non-friend
