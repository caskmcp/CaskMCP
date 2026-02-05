# MCPMint Task Plan

## Goal
Build MCPMint: an open-core "action surface compiler" that turns observed web/API behavior into safe, versioned, agent-ready tools with drift detection and enforcement guardrails.

## Current Phase
Phase 14: Full Package Rename + Compatibility

## Phases

### Phase 1: Foundation Setup `complete`
- [x] Create repo structure
- [x] Set up CLAUDE.md
- [x] Initialize git
- [x] Create planning files
- [x] Create SPEC.md (detailed architecture)
- [x] Create README.md (product positioning)
- [x] Set up pyproject.toml
- [x] Create core module structure
- [x] Port HAR parser from API Scout
- [x] Port endpoint normalizer from API Scout

### Phase 2: Scope Engine `complete`
- [x] Define Scope YAML DSL format
- [x] Implement 5 built-in scopes:
  - first_party_only
  - auth_surface
  - state_changing
  - pii_surface
  - agent_safe_readonly
- [x] Scope selection/filtering logic
- [x] Risk classification rules

### Phase 3: Contract Compiler `complete`
- [x] OpenAPI 3.1 generator
- [x] Stable endpoint IDs (hash-based)
- [x] Schema inference with confidence scores
- [x] Examples with redaction

### Phase 4: Tool Manifest Generator `complete`
- [x] Tool Manifest JSON schema
- [x] Action extraction from contracts
- [x] Risk tier assignment
- [x] Input/output schema generation
- [x] Policy generator
- [x] Baseline generator
- [x] CLI compile command wired up

### Phase 5: Drift Engine `complete`
- [x] Baseline snapshot storage (in BaselineGenerator)
- [x] Diff algorithm (endpoint-level)
- [x] Schema-level drift detection
- [x] Drift classification:
  - Breaking drift (removed endpoints, response schema breaks)
  - Auth drift (auth type changes)
  - Risk drift (new state-changing endpoints, risk tier escalation)
  - Additive drift (new read-only endpoints)
  - Schema drift (non-breaking schema changes)
  - Parameter drift (parameter added/removed)
  - Unknown drift (unclassified)
- [x] CI-friendly output and exit codes (0=ok, 1=warning, 2=breaking)
- [x] JSON and Markdown report generation
- [x] CLI `mcpmint drift` command

### Phase 6: Policy Engine `complete`
- [x] Policy models (Policy, PolicyRule, MatchCondition, RuleType, EvaluationResult)
- [x] Policy YAML format with parser
- [x] Allowlist/denylist rules with priority-based evaluation
- [x] Confirmation rules with custom messages
- [x] Budget/rate limiting rules (per-minute, per-hour)
- [x] Redaction rules for headers and patterns
- [x] Audit rules with configurable levels
- [x] PolicyEngine with full evaluation logic
- [x] Test suite (22 tests)

### Phase 7: Enforcer (Agent Firewall) `complete`
- [x] Runtime gate for tool calls (Enforcer class)
- [x] Policy evaluation (wraps PolicyEngine)
- [x] Confirmation workflow (request/confirm/deny with tokens)
- [x] Confirmation timeout and expiry
- [x] Audit logging (JSONL format with event types)
- [x] File and Memory audit backends
- [x] Budget tracking integration
- [x] Test suite (19 tests)

### Phase 8: CLI Commands `complete`
- [x] `mcpmint capture import` - HAR file import (Playwright capture pending)
- [x] `mcpmint compile` - Generate artifacts (contracts, tools, policy, baseline)
- [x] `mcpmint drift` - Compare captures/baselines with CI exit codes
- [x] `mcpmint enforce` - HTTP gateway with policy enforcement
- [ ] `mcpmint serve` - Local dashboard (optional, deferred)

### Phase 9: Chrome Extension `pending`
- [ ] Fork from API Scout extension
- [ ] Rebrand to MCPMint
- [ ] Session capture for tool auth
- [ ] Scope-aware capture

### Phase 10: Documentation & Polish `complete`
- [x] User guide (docs/user-guide.md)
- [x] Example HAR file (examples/sample.har)
- [x] Example README with demo workflow
- [x] GitHub Actions CI workflow (.github/workflows/ci.yaml)
- [x] GitHub Actions drift check template (.github/workflows/drift-check.yaml.example)
- [ ] API reference (deferred)
- [ ] 60-90 second demo video script (deferred)

### Phase 11: Code Quality `complete`
- [x] Fixed all ruff lint errors (92 total)
- [x] Fixed all mypy type errors (13 total)
- [x] Migrated to StrEnum for cleaner enum definitions
- [x] Full test suite passing (129 tests)

### Phase 12: Mint Loop + Toolpacks `complete`
- [x] Add first-class toolpack model and layout (`toolpack.yaml`, `artifact/`, `lockfile/`)
- [x] Add `mcpmint mint` command (capture -> compile -> pending approvals -> toolpack)
- [x] Extend Playwright capture for headless + scripted capture runner hook
- [x] Add `mcpmint mcp serve --toolpack` path resolution with explicit-flag override
- [x] Add mock-based tests for mint and MCP toolpack resolution
- [x] Run full regression suite and finalize docs/demo wording

### Phase 13: Rename to MCPMint + Proxy Lockfile Strictness `complete`
- [x] Add rename scaffold (branding constants + `mcpmint` primary CLI)
- [x] Update top-level docs messaging to MCPMint
- [x] Validate name availability on key registries (PyPI/npm + AI-adjacent collision sweep)
- [x] Require lockfile in proxy mode by default
- [x] Add explicit `--unsafe-no-lockfile` escape hatch
- [x] Add/adjust tests and run full regression suite

### Phase 14: Full Package Rename + Cleanup `complete`
- [x] Move primary package to `mcpmint/`
- [x] Switch defaults to `.mcpmint/` and `mcpmint.lock.yaml`
- [x] Rename MCP server identities/user-agent to `mcpmint`
- [x] Remove compatibility alias package/entrypoint
- [x] Remove legacy fallback paths to keep first public release clean
- [x] Update packaging (`pyproject.toml`) to ship `mcpmint` only
- [x] Add build excludes for local runtime state/temp directories
- [x] Update tests to primary `mcpmint` import paths and assertions
- [x] Run full regression suite (`267 passed`)

## Decisions Made
| Decision | Rationale | Date |
|----------|-----------|------|
| New repo instead of refactor | Clean identity, trust signal, different architecture | 2025-02-04 |
| Python + Click CLI | Consistent with API Scout, good ecosystem | 2025-02-04 |
| YAML for Scopes/Policy | Human-readable, easy to version control | 2025-02-04 |

## Errors Encountered
| Error | Attempt | Resolution |
|-------|---------|------------|
| (none yet) | | |

## Files Created/Modified
- CLAUDE.md
- .gitignore
- task_plan.md
- findings.md
- progress.md
- SPEC.md (comprehensive architecture specification)
- README.md (product positioning)
- pyproject.toml (package configuration)
- mcpmint/ (complete package structure)
  - cli/ (main.py, capture.py, compile.py, drift.py, enforce.py, serve.py)
  - core/capture/ (har_parser.py, redactor.py)
  - core/normalize/ (path_normalizer.py, aggregator.py)
  - core/scope/, compile/, drift/, enforce/, audit/ (placeholders)
  - models/ (capture.py, endpoint.py)
  - storage/ (filesystem.py)
  - utils/ (naming.py)
- tests/ (test_har_parser.py - 18 tests, test_scope.py - 21 tests)
- mcpmint/models/scope.py (Scope, ScopeRule, ScopeFilter models)
- mcpmint/core/scope/ (engine.py, builtins.py, parser.py)
