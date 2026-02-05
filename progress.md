# MCPMint Progress Log

## Session: 2026-02-05

### Full Package Rename + Cleanup

- [x] Renamed primary Python package to `mcpmint/`.
- [x] Promoted new defaults:
  - state dir: `.mcpmint/`
  - lockfile: `mcpmint.lock.yaml`
  - pending lockfile: `mcpmint.lock.pending.yaml`
  - confirmations DB: `.mcpmint/confirmations.db`
  - MCP server IDs/user-agent: `mcpmint`, `mcpmint-meta`, `MCPMint-*`
- [x] Updated packaging metadata:
  - wheel packages include `mcpmint` only
  - CLI script uses `mcpmint` only
  - project URLs moved to `.../mcpmint`
  - hatch build excludes for local state/temp artifacts (`.mcpmint`, `tmp_magic_demo`, caches)
- [x] Updated test suite imports and assertions to primary `mcpmint` module paths.
- [x] Validation:
  - full suite: `267 passed`

### Governance Hardening + Documentation Sync

- [x] Added runtime lockfile gating to proxy enforcement (`--lockfile` required in proxy mode).
- [x] Added manifest/enforcer compatibility for both endpoint field shapes (top-level and nested).
- [x] Shifted lockfile identity to signature-first while preserving operator-friendly lookup fallbacks.
- [x] Added artifact `schema_version` to manifests, policy, baseline, lockfile, and drift report with load-time validation.
- [x] Switched deterministic metadata to default for governance workflows:
  - compile / drift / approve sync now deterministic by default
  - explicit opt-out: `--volatile-metadata`
- [x] Added deterministic drift support with stable drift/report IDs and deterministic timestamps.
- [x] Introduced first-class toolsets artifact (`toolsets.yaml`) generated during compile.
- [x] Added MCP toolset selection + enforcement:
  - `mcp serve --toolsets <toolsets.yaml> --toolset <name>`
  - defaults to `readonly` toolset and validates schema + referenced tools
- [x] Added optional MCP lockfile approval enforcement:
  - `mcp serve` default remains non-blocking for approvals
  - passing `--lockfile` filters exposed MCP tools to approved actions
  - supports toolset-scoped approvals when toolset is selected
- [x] Added toolset-scoped lockfile governance:
  - lockfile tracks `toolsets` membership and `approved_toolsets` per tool
  - `approve sync` can ingest toolsets artifact (auto-detects sibling `toolsets.yaml`)
  - `approve tool --toolset <name>` supports scoped approvals
  - `approve check --toolset <name>` gates CI by rollout toolset
- [x] Added enforce gateway toolset controls:
  - `enforce --toolsets <toolsets.yaml> --toolset <name>` filters runtime action surface
  - proxy runtime checks support selected toolset context with lockfile metadata
- [x] Updated docs to match actual behavior:
  - `README.md`
  - `docs/user-guide.md`
  - `examples/demo.sh`
- [x] Validation:
  - full suite: `239 passed`
  - targeted lint on touched Python files: `ruff check` passed

### Mint Loop + Toolpacks

- [x] Added first-class toolpack schema + resolver (`mcpmint/core/toolpack.py`).
- [x] Added `mcpmint mint` orchestration command:
  - Playwright capture (headless default), optional scripted flow hook, duration window
  - Redaction-on capture persistence
  - Compile to deterministic artifacts
  - Toolpack creation under `.mcpmint/toolpacks/<toolpack_id>/`
  - Pending lockfile generation (`mcpmint.lock.pending.yaml`) via approval sync logic
  - Optional Claude Desktop MCP config snippet output
- [x] Refactored compile pipeline into reusable helper (`compile_capture_session`) for CLI/mint reuse.
- [x] Extended capture CLI record mode with `--headless`, `--script`, and `--duration`.
- [x] Added MCP server `--toolpack` support with explicit `--tools/--toolsets/--policy/--lockfile` override precedence.
- [x] Added tests:
  - `tests/test_mint.py`
  - `tests/test_mcp_cli.py`
  - scripted capture execution path in `tests/test_playwright_capture.py`
- [x] Updated docs/spec/demo assets:
  - `README.md`
  - `docs/user-guide.md`
  - `SPEC.md`
  - `examples/mint_demo.sh`

### Rename to MCPMint + Proxy Lockfile Strictness

- [x] Added staged rename scaffold:
  - `mcpmint/branding.py` for product/command constants
  - primary CLI entrypoint `mcpmint` in `pyproject.toml`
  - updated top-level docs to MCPMint
- [x] Finalized project naming to **MCPMint** after availability checks across:
  - PyPI package JSON endpoints (`mcpmint`, `mcp-mint`, `mcp_mint`) -> `404` (available)
  - npm package registry (`mcpmint`, `mcp-mint`, `mcp_mint`) -> `404` (available)
  - quick AI-adjacent collision checks (Hugging Face profile route) -> no claim found
- [x] Hardened proxy governance defaults:
  - `enforce --mode=proxy` now requires lockfile by default
  - explicit unsafe escape hatch: `--unsafe-no-lockfile`
  - runtime warning when unsafe mode is used
- [x] Added tests for:
  - gateway strict proxy lockfile requirement + unsafe override
  - CLI wiring for `--unsafe-no-lockfile`
- [x] Validation:
  - full suite: `266 passed`

## Session: 2025-02-04

### Work Completed

#### Foundation Setup
- [x] Created mcpmint repo at /Users/thomasallicino/Documents/mcpmint
- [x] Initialized git repository (main branch)
- [x] Created CLAUDE.md with MCPMint-specific design principles
- [x] Created .gitignore
- [x] Created planning files (task_plan.md, findings.md, progress.md)

#### SPEC.md Created
- [x] Created comprehensive SPEC.md (~800 lines) with:
  - System architecture diagrams (ASCII)
  - Data flow diagrams
  - Core module structure (mcpmint/ tree)
  - All Pydantic data models:
    - Capture: HttpExchange, CaptureSession
    - Endpoint: Endpoint, Parameter
    - Action: Action, ToolManifest
    - Policy: PolicyRule, Policy
    - Drift: DriftItem, DriftReport
    - Scope: Scope, ScopeRule
  - Scope DSL specification (YAML format)
  - 5 built-in scopes defined:
    - first_party_only
    - auth_surface
    - state_changing
    - pii_surface
    - agent_safe_readonly
  - Policy DSL specification (YAML format)
  - All 5 CLI commands specified
  - Storage format (directory structure, IDs, audit log)
  - 8 key protocol interfaces
  - Extension points (adapters, providers, classifiers)
  - Non-negotiable defaults table
  - Implementation priority (5 phases)
  - 3 appendices with examples

#### GitHub Remote Added
- Repository: https://github.com/tomallicino/MCPMint.git

#### README.md Created
- [x] Product positioning and quick start guide
- [x] Usage examples for all CLI commands
- [x] Safety defaults explanation
- [x] Use case descriptions

#### pyproject.toml Created
- [x] Package metadata and dependencies
- [x] CLI entry point (`mcpmint` command)
- [x] Dev dependencies (pytest, ruff, mypy)
- [x] Optional extras (mcp, playwright)
- [x] Tool configurations (ruff, mypy, pytest, coverage)

#### Core Module Structure Implemented
- [x] Complete package structure with all modules:
  - `mcpmint/cli/` - All 5 CLI commands (capture, compile, drift, enforce, serve)
  - `mcpmint/core/capture/` - HARParser, Redactor
  - `mcpmint/core/normalize/` - PathNormalizer, EndpointAggregator
  - `mcpmint/core/scope/` - (placeholder)
  - `mcpmint/core/compile/` - (placeholder)
  - `mcpmint/core/drift/` - (placeholder)
  - `mcpmint/core/enforce/` - (placeholder)
  - `mcpmint/core/audit/` - (placeholder)
  - `mcpmint/models/` - CaptureSession, HttpExchange, Endpoint, Parameter
  - `mcpmint/storage/` - Filesystem storage
  - `mcpmint/utils/` - Tool naming with verb_noun pattern
- [x] CLI entry point working: `mcpmint --version` and `--help`

#### HAR Parser Ported
- [x] Full HAR parsing from API Scout
- [x] Host filtering with wildcard support
- [x] Static file filtering
- [x] API request detection heuristics
- [x] JSON body parsing
- [x] Comprehensive test suite (6 tests)

#### Endpoint Normalizer Ported
- [x] Path normalization (UUIDs, numeric IDs, ObjectIds, tokens)
- [x] Variance-based path learning across samples
- [x] Endpoint aggregation and deduplication
- [x] Auth detection from headers
- [x] PII detection in request/response bodies
- [x] Risk tier classification
- [x] Test suite for path normalization (4 tests)

#### Tool Naming Implementation
- [x] verb_noun pattern from STRATEGY.md
- [x] Method-to-verb mapping (GET→get, POST→create, etc.)
- [x] Verb overrides for special patterns (search, login, graphql)
- [x] Singularization for resources (users→user)
- [x] Read-only POST detection (search, query keep plural)
- [x] Collision resolution with host namespacing
- [x] Test suite (8 tests, all passing)

#### Redactor Implementation
- [x] Header redaction (authorization, cookie, api-key, etc.)
- [x] URL query param redaction
- [x] Body pattern redaction (bearer tokens, JWTs, passwords)
- [x] Recursive dict/list redaction

#### Tests
- [x] 18 tests passing
- [x] HAR parser tests
- [x] Path normalizer tests
- [x] Tool naming tests

#### Scope Engine Implemented (Phase 2)
- [x] Scope data models (Scope, ScopeRule, ScopeFilter)
- [x] Filter operators (equals, not_equals, contains, matches, in, not_in)
- [x] ScopeEngine with load_scope, filter_endpoints, classify_endpoint
- [x] 5 built-in scopes:
  - `first_party_only` - First-party domain filter
  - `auth_surface` - Auth endpoints (login, token, session, etc.)
  - `state_changing` - POST/PUT/PATCH/DELETE (excludes search/graphql)
  - `pii_surface` - User/profile endpoints + PII detection
  - `agent_safe_readonly` - Safe GET subset (no auth, no PII, no admin)
- [x] YAML DSL parser for custom scopes
- [x] Scope serialization for export
- [x] Test suite (21 tests)

#### Contract Compiler Implemented (Phase 3)
- [x] OpenAPI 3.1 generator (ContractCompiler)
- [x] Stable endpoint IDs (hash-based signature_id, tool_id, tool_version)
- [x] x-mcpmint metadata extension for risk/state-changing info
- [x] Server extraction from hosts
- [x] Parameter compilation (path, query, header)
- [x] Request/response schema inclusion
- [x] YAML and JSON serialization
- [x] Test suite (8 tests)

#### Tool Manifest Generator Implemented (Phase 4)
- [x] Tool manifest JSON schema
- [x] Action extraction with verb_noun naming
- [x] Risk tier assignment and confirmation rules
- [x] Input/output schema generation
- [x] Rate limit recommendations by risk tier
- [x] PolicyGenerator for default policy rules
- [x] BaselineGenerator for drift snapshots
- [x] CLI `mcpmint compile` command wired up
- [x] Test suite (17 tests)

#### Drift Engine Implemented (Phase 5)
- [x] DriftEngine with compare() and compare_to_baseline()
- [x] Drift models (DriftType, DriftSeverity, DriftItem, DriftReport)
- [x] Drift classification:
  - BREAKING (removed endpoints, response schema breaks)
  - AUTH (auth type changes)
  - RISK (new state-changing, risk tier escalation)
  - ADDITIVE (new read-only endpoints)
  - SCHEMA (non-breaking schema changes)
  - PARAMETER (parameter added/removed)
  - UNKNOWN (unclassified)
- [x] CI-friendly exit codes (0=ok, 1=warning, 2=breaking)
- [x] JSON and Markdown report generation
- [x] CLI `mcpmint drift` command
- [x] Test suite (24 tests)

#### Tests Summary
- 88 tests total (all passing)
- test_har_parser.py: 18 tests
- test_scope.py: 21 tests
- test_compile.py: 25 tests
- test_drift.py: 24 tests

#### Policy Engine Implemented (Phase 6)
- [x] Policy models (Policy, PolicyRule, MatchCondition, RuleType, EvaluationResult)
- [x] MatchCondition with host, path, method, risk tier matching
- [x] PolicyEngine with priority-based rule evaluation
- [x] Allowlist/denylist rules
- [x] Confirmation rules with custom messages
- [x] Budget/rate limiting rules (BudgetTracker)
- [x] Redaction rules for headers and patterns
- [x] Audit rules with configurable levels
- [x] YAML parser for policy files
- [x] Test suite (22 tests)

#### Enforcer (Agent Firewall) Implemented (Phase 7)
- [x] Enforcer class wrapping PolicyEngine
- [x] Confirmation workflow (request/confirm/deny)
- [x] Confirmation tokens with timeout/expiry
- [x] AuditLogger with JSONL format
- [x] Event types: enforce_decision, confirmation_requested/granted/denied, etc.
- [x] FileAuditBackend and MemoryAuditBackend
- [x] Test suite (19 tests)

#### CLI Commands Implemented (Phase 8)
- [x] `mcpmint capture import` - HAR file import with redaction
- [x] `mcpmint compile` - Generate all artifacts
- [x] `mcpmint drift` - Compare captures/baselines, CI exit codes
- [x] `mcpmint enforce` - HTTP gateway server
  - GET /health, /actions, /policy, /pending
  - POST /evaluate, /confirm, /deny
- [ ] `mcpmint serve` - Dashboard (deferred)

#### Tests Summary
- 129 tests total (all passing)
- test_har_parser.py: 18 tests
- test_scope.py: 21 tests
- test_compile.py: 25 tests
- test_drift.py: 24 tests
- test_policy.py: 22 tests
- test_enforcer.py: 19 tests

#### Documentation & Polish (Phase 10)
- [x] User guide (docs/user-guide.md)
  - Complete workflow documentation
  - CLI command reference
  - Scopes and policies explanation
  - CI/CD integration guide
  - Troubleshooting section
- [x] Example files (examples/)
  - sample.har - Demo HAR file with 8 endpoints
  - README.md - Quick demo instructions
- [x] GitHub Actions workflows (.github/workflows/)
  - ci.yaml - Test and build pipeline
  - drift-check.yaml.example - Drift detection template
- [x] Bug fix: Storage path for captures

#### Code Quality (Phase 11)
- [x] Fixed all 92 ruff lint errors
  - Import sorting and unused imports
  - Ternary operators for simple if/else
  - Combined nested if statements
  - contextlib.suppress for silent exceptions
  - Set comprehensions instead of generator + set()
  - Removed unused variables
  - raise from err for exception chaining
  - Simplified return statements
  - Migrated from (str, Enum) to StrEnum (Python 3.11+)
- [x] Fixed all 13 mypy type errors
  - Added missing type annotations for dict parameters
  - Fixed return type annotations for json.load
  - Added explicit type annotations for variables
  - Fixed function signature mismatches
- [x] All 129 tests passing
- [x] Full type checking passes (mypy)

#### MCP Server (Phase 12 - Option B Priority)
- [x] Implemented MCPMintMCPServer class
  - Loads tools.json manifest
  - Exposes tools as MCP protocol tools
  - Integrates with Enforcer for policy evaluation
  - Forwards requests to upstream APIs (with auth support)
  - Dry-run mode for testing
  - Audit logging integration
- [x] CLI command `mcpmint mcp serve`
  - --tools: Path to tools.json manifest
  - --policy: Optional policy.yaml for enforcement
  - --base-url: Override upstream API URL
  - --auth: Authorization header for upstream
  - --audit-log: Path for audit logging
  - --dry-run: Evaluate without executing
- [x] Claude Desktop configuration example in help
- [x] Test suite (9 tests)
- [x] All 138 tests passing

#### Approval Lockfile (Phase 13 - P0-3)
- [x] Implemented approval lockfile workflow
  - LockfileManager class with sync, approve, reject, check_ci methods
  - ApprovalStatus enum (PENDING, APPROVED, REJECTED)
  - ToolApproval Pydantic model with version tracking
- [x] CLI command `mcpmint approve` with subcommands:
  - sync: Sync lockfile with tools manifest
  - list: List tool approvals with status filter
  - tool: Approve one or more tools
  - reject: Reject tools with reason
  - check: CI gate (exit 0 if all approved)
- [x] Test suite (28 tests)

#### 60-Second Demo (Phase 14 - P0-4)
- [x] Created examples/demo.sh interactive demo script
  - HAR import → compile → approve → MCP workflow
  - Demonstrates full end-to-end path
- [x] README rewrite with working demo instructions

#### Meta MCP Server (Phase 15 - P1-7)
- [x] Implemented MCPMintMetaMCPServer
  - Exposes governance tools to AI agents
  - Tools: list_actions, check_policy, get_approval_status, etc.
- [x] CLI command `mcpmint mcp meta`
- [x] Test suite (13 tests)

#### OpenAPI Import (Phase 16 - P2-10)
- [x] Implemented OpenAPIParser class
  - Parses OpenAPI 3.0/3.1 specifications
  - Converts to CaptureSession with synthetic exchanges
  - Resolves $ref pointers, generates examples from schemas
- [x] CLI command `mcpmint openapi`
- [x] Test suite (15 tests)

#### Playwright Capture (Phase 17 - P1-6)
- [x] Implemented PlaywrightCapture class
  - Interactive browser capture mode
  - Network interception with host filtering
  - API request detection (content-type, URL patterns)
  - Graceful Ctrl+C shutdown
- [x] CLI command `mcpmint capture record`
- [x] Test suite (21 tests)
- [x] All 215 tests passing

#### Proxy/Execute Mode (Phase 18 - P0-2)
- [x] Implemented proxy mode for enforce gateway
  - `--mode=proxy`: Forward requests to upstream API
  - `--base-url`: Override upstream URL
  - `--auth`: Set authorization header
  - `/execute` endpoint: Evaluate + proxy in one call
- [x] Async HTTP execution with httpx
- [x] Audit logging for executed requests
- [x] Test suite (12 tests)
- [x] All 227 tests passing

#### Remaining
- [ ] **P2-8: Chrome Extension** - Browser extension for capture
- [ ] **P2-9: Dashboard UI** - Web UI for browsing artifacts

### Decisions
| Decision | Rationale |
|----------|-----------|
| Python 3.11+ | Modern features, good typing support |
| Click for CLI | Clean API, good help generation |
| Pydantic for models | Validation, serialization, JSON Schema |
| YAML for config | Human-readable, versionable |

### TDD Exceptions
| Exception | Reason |
|-----------|--------|
| Initial setup | Docs/config only, no behavior yet |

### Errors
(none yet)

---

## Previous Sessions
(new repo)
