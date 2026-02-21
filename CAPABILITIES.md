# Cask Capability Registry

> Canonical map of all existing user-visible capabilities.
> Every entry includes file paths and entry points.
> **Existing-only** -- no roadmap items.

---

## Table of Contents

- [CLI Commands -- Core](#cli-commands----core)
- [CLI Commands -- More](#cli-commands----more)
- [CLI Commands -- Advanced / Hidden](#cli-commands----advanced--hidden)
- [Core Domain -- Capture & Parsing](#core-domain----capture--parsing)
- [Core Domain -- Normalization](#core-domain----normalization)
- [Core Domain -- Compilation](#core-domain----compilation)
- [Core Domain -- Scope Filtering](#core-domain----scope-filtering)
- [Core Domain -- Approval & Signing](#core-domain----approval--signing)
- [Core Domain -- Drift Detection](#core-domain----drift-detection)
- [Core Domain -- Policy Enforcement](#core-domain----policy-enforcement)
- [Core Domain -- Verification](#core-domain----verification)
- [Core Domain -- MCP Server](#core-domain----mcp-server)
- [Core Domain -- Proposals](#core-domain----proposals)
- [System Responsibilities](#system-responsibilities)

---

## CLI Commands -- Core

### CAP-CLI-001: init

Initialize Cask in a project directory. Auto-detects project type, generates config, and prints next steps.

| Field | Value |
|---|---|
| Command | `cask init` |
| CLI file | `caskmcp/cli/main.py` :: `init_cmd` |
| Implementation | `caskmcp/cli/init.py` :: `run_init` |
| Domain module | `caskmcp/core/init/__init__.py` |
| Key options | `--directory`, `--non-interactive` |

---

### CAP-CLI-002: mint

One-command capture + compile pipeline. Captures browser traffic via Playwright and compiles a governed toolpack including tools manifest, policy, contracts, baseline, toolsets, and lockfile. Prints progress output (minting, capturing, compiling) to keep users informed. Performs a best-effort auth pre-check against allowed hosts before capture starts, warning if 401/403 is detected.

| Field | Value |
|---|---|
| Command | `cask mint <START_URL> -a <HOST>` |
| CLI file | `caskmcp/cli/main.py` :: `mint` |
| Implementation | `caskmcp/cli/mint.py` :: `run_mint` |
| Auth pre-check | `caskmcp/cli/mint.py` :: `_auth_precheck` |
| Key options | `--scope` (default: `first_party_only`), `--headless`, `--script`, `--duration`, `--runtime`, `--runtime-build`, `--print-mcp-config`, `--auth-profile`, `--webmcp`, `--redaction-profile`, `--deterministic` |

---

### CAP-CLI-003: diff

Generate a risk-classified change report comparing a toolpack against a baseline.

| Field | Value |
|---|---|
| Command | `cask diff --toolpack <PATH>` |
| CLI file | `caskmcp/cli/main.py` :: `diff` |
| Implementation | `caskmcp/cli/plan.py` :: `run_plan` |
| Domain module | `caskmcp/core/plan/__init__.py` |
| Key options | `--baseline`, `--output`, `--format` (json, markdown, github-md, both) |

---

### CAP-CLI-004: gate

Approval workflow group with subcommands for lockfile-based governance of tools.

| Field | Value |
|---|---|
| Command | `cask gate <subcommand>` |
| CLI file | `caskmcp/cli/commands_approval.py` :: `register_approval_commands` |
| Implementation | `caskmcp/cli/approve.py` |

#### CAP-CLI-004a: gate sync

Sync lockfile with a tools manifest. New tools are added as pending, modified tools require re-approval.

| Field | Value |
|---|---|
| Command | `cask gate sync --tools <PATH>` |
| Entry point | `caskmcp/cli/approve.py` :: `run_approve_sync` |
| Key options | `--policy`, `--toolsets`, `--lockfile`, `--capture-id`, `--scope`, `--prune-removed`, `--deterministic` |

#### CAP-CLI-004b: gate status

List tool approvals from the lockfile with optional status filtering.

| Field | Value |
|---|---|
| Command | `cask gate status` |
| Entry point | `caskmcp/cli/approve.py` :: `run_approve_list` |
| Key options | `--lockfile`, `--status` (pending, approved, rejected) |

#### CAP-CLI-004c: gate allow

Approve one or more tools (or all pending) for use with Ed25519 signing.

| Field | Value |
|---|---|
| Command | `cask gate allow <TOOL_IDS...>` |
| Entry point | `caskmcp/cli/approve.py` :: `run_approve_tool` |
| Key options | `--all`, `--toolset`, `--by`, `--reason`, `--lockfile` |

#### CAP-CLI-004d: gate block

Reject/block tools. Blocked tools cause CI gate checks to fail.

| Field | Value |
|---|---|
| Command | `cask gate block <TOOL_IDS...>` |
| Entry point | `caskmcp/cli/approve.py` :: `run_approve_reject` |
| Key options | `--reason`, `--lockfile` |

#### CAP-CLI-004e: gate check

CI gate: exit 0 if all tools approved, exit 1 if pending/rejected, exit 2 if no lockfile.

| Field | Value |
|---|---|
| Command | `cask gate check` |
| Entry point | `caskmcp/cli/approve.py` :: `run_approve_check` |
| Key options | `--lockfile`, `--toolset` |

#### CAP-CLI-004f: gate snapshot

Materialize a baseline snapshot from an approved lockfile.

| Field | Value |
|---|---|
| Command | `cask gate snapshot` |
| Entry point | `caskmcp/cli/approve.py` :: `run_approve_snapshot` |
| Key options | `--lockfile` |

#### CAP-CLI-004g: gate reseal

Re-sign existing approval signatures (migration/repair helper).

| Field | Value |
|---|---|
| Command | `cask gate reseal` |
| Entry point | `caskmcp/cli/approve.py` :: `run_approve_resign` |
| Key options | `--lockfile`, `--toolset` |

---

### CAP-CLI-005: serve

Start the governed MCP server on stdio transport. Exposes compiled tools as callable actions with policy enforcement, confirmation requirements, lockfile integrity gating, and audit logging.

| Field | Value |
|---|---|
| Command | `cask serve --toolpack <PATH>` |
| CLI file | `caskmcp/cli/commands_mcp.py` :: `register_mcp_commands` (serve) |
| Implementation | `caskmcp/cli/mcp.py` :: `run_mcp_serve` |
| Server class | `caskmcp/mcp/server.py` :: `CaskMCPMCPServer` |
| Key options | `--tools`, `--toolpack`, `--toolsets`, `--toolset`, `--policy`, `--lockfile`, `--base-url`, `--auth`, `--audit-log`, `--dry-run`, `--confirm-store`, `--allow-private-cidr`, `--allow-redirects`, `--unsafe-no-lockfile` |

---

### CAP-CLI-006: run

Execute a toolpack with policy enforcement. Higher-level wrapper around serve with runtime selection (local or container).

| Field | Value |
|---|---|
| Command | `cask run --toolpack <PATH>` |
| CLI file | `caskmcp/cli/main.py` :: `run` |
| Implementation | `caskmcp/cli/run.py` :: `run_run` |
| Key options | `--runtime` (auto, local, container), `--print-config-and-exit`, `--toolset`, `--lockfile`, `--base-url`, `--auth`, `--audit-log`, `--dry-run`, `--confirm-store`, `--allow-private-cidr`, `--allow-redirects`, `--unsafe-no-lockfile` |

---

### CAP-CLI-007: drift

Detect drift between captures or against a baseline. Reports breaking changes, auth changes, risk escalations, schema changes, and parameter changes.

| Field | Value |
|---|---|
| Command | `cask drift --from <ID> --to <ID>` or `cask drift --baseline <PATH> --capture-id <ID>` |
| CLI file | `caskmcp/cli/main.py` :: `drift` |
| Implementation | `caskmcp/cli/drift.py` :: `run_drift` |
| Domain engine | `caskmcp/core/drift/engine.py` :: `DriftEngine` |
| Key options | `--from`, `--to`, `--baseline`, `--capture-id`, `--capture-path`, `--output`, `--format`, `--deterministic` |

---

### CAP-CLI-008: verify

Run verification contracts: contract schema validation, deterministic replay (baseline-check), outcomes checking, and provenance scoring. The `replay` mode is now wired to the core `run_replay()` function for real endpoint presence and schema compatibility checking. `baseline-check` is the preferred mode name (`replay` is kept as a deprecated alias).

| Field | Value |
|---|---|
| Command | `cask verify --toolpack <PATH>` |
| CLI file | `caskmcp/cli/main.py` :: `verify` |
| Implementation | `caskmcp/cli/verify.py` :: `run_verify` |
| Domain engine | `caskmcp/core/verify/engine.py` :: `VerifyEngine` |
| Sub-engines | `caskmcp/core/verify/contracts.py`, `caskmcp/core/verify/replay.py`, `caskmcp/core/verify/outcomes.py`, `caskmcp/core/verify/provenance.py` |
| Key options | `--mode` (contracts, baseline-check, replay, outcomes, provenance, all), `--lockfile`, `--playbook`, `--ui-assertions`, `--strict`, `--top-k`, `--min-confidence`, `--unknown-budget` |

---

### CAP-CLI-009: demo

One-command proof of governance enforcement. Proves governance is enforced, replays are deterministic, and parity passes. Supports offline, live browser, and smoke test modes.

| Field | Value |
|---|---|
| Command | `cask demo` |
| CLI file | `caskmcp/cli/main.py` :: `demo` |
| Implementation (offline fixture) | `caskmcp/cli/demo.py` :: `run_demo` |
| Implementation (prove flow) | `caskmcp/cli/wow.py` :: `run_wow`, `run_prove_smoke` |
| Key options | `--out`, `--live`, `--scenario`, `--keep`, `--smoke`, `--smoke-scenarios`, `--generate-only` |

---

### CAP-CLI-013: config

Print a ready-to-paste MCP client config snippet (Claude Desktop, Cursor, Codex). Server name is auto-derived from the toolpack origin (start_url host → kebab-case) for readable MCP config output, falling back to the toolpack ID if no origin is set.

| Field | Value |
|---|---|
| Command | `cask config --toolpack <PATH>` |
| CLI file | `caskmcp/cli/main.py` :: `config` |
| Implementation | `caskmcp/cli/config.py` :: `run_config` |
| Name derivation | `caskmcp/cli/config.py` :: `_derive_server_name` |
| Key options | `--name`, `--format` (json, yaml, codex) |

---

## CLI Commands -- More

### CAP-CLI-010: capture

Import traffic from HAR/OTEL/OpenAPI files or record interactively with Playwright.

| Field | Value |
|---|---|
| Command | `cask capture import <SOURCE> -a <HOST>` or `cask capture record <URL> -a <HOST>` |
| CLI file | `caskmcp/cli/main.py` :: `capture` |
| Implementation | `caskmcp/cli/capture.py` :: `run_capture`, `run_capture_openapi` |
| Parsers | `caskmcp/core/capture/har_parser.py` :: `HARParser`, `caskmcp/core/capture/otel_parser.py` :: `OTELParser`, `caskmcp/core/capture/openapi_parser.py` :: `OpenAPIParser` |
| Playwright capture | `caskmcp/core/capture/playwright_capture.py` :: `PlaywrightCapture` |
| Key options | `--allowed-hosts` (required), `--name`, `--output`, `--input-format` (har, otel, openapi), `--no-redact`, `--headless`, `--script`, `--duration`, `--load-storage-state`, `--save-storage-state` |

---

### CAP-CLI-011: workflow

Tide integration: verification-first workflow runner with multi-step workflows (shell, HTTP, browser, MCP steps).

| Field | Value |
|---|---|
| Command | `cask workflow <subcommand>` |
| CLI file | `caskmcp/cli/commands_workflow.py` :: `register_workflow_commands` |

#### CAP-CLI-011a: workflow init

Create a starter workflow YAML file.

| Field | Value |
|---|---|
| Command | `cask workflow init [PATH]` |
| Entry point | `caskmcp/cli/commands_workflow.py` :: `workflow_init` |

#### CAP-CLI-011b: workflow run

Execute a workflow and emit a verification bundle with evidence and digests.

| Field | Value |
|---|---|
| Command | `cask workflow run <WORKFLOW_FILE>` |
| Entry point | `caskmcp/cli/commands_workflow.py` :: `workflow_run` |
| Tide runner | `tide.core.runner` :: `run_workflow` |

#### CAP-CLI-011c: workflow replay

Replay a previous run using its resolved workflow.

| Field | Value |
|---|---|
| Command | `cask workflow replay <RUN_DIR>` |
| Entry point | `caskmcp/cli/commands_workflow.py` :: `workflow_replay` |

#### CAP-CLI-011d: workflow diff

Compare two workflow runs with step-level diffs.

| Field | Value |
|---|---|
| Command | `cask workflow diff <RUN_A> <RUN_B>` |
| Entry point | `caskmcp/cli/commands_workflow.py` :: `workflow_diff` |
| Key options | `--format` (github-md, json) |

#### CAP-CLI-011e: workflow report

Generate a report (Markdown or JSON) for a completed run.

| Field | Value |
|---|---|
| Command | `cask workflow report <RUN_DIR>` |
| Entry point | `caskmcp/cli/commands_workflow.py` :: `workflow_report` |

#### CAP-CLI-011f: workflow pack

Pack a run directory into a portable zip.

| Field | Value |
|---|---|
| Command | `cask workflow pack <RUN_DIR>` |
| Entry point | `caskmcp/cli/commands_workflow.py` :: `workflow_pack` |

#### CAP-CLI-011g: workflow export

Export artifacts for other tools (e.g. HAR for cask capture import).

| Field | Value |
|---|---|
| Command | `cask workflow export cask <RUN_DIR>` |
| Entry point | `caskmcp/cli/commands_workflow.py` :: `workflow_export` |

#### CAP-CLI-011h: workflow doctor

Check optional workflow dependencies (Playwright, MCP SDK, Tide).

| Field | Value |
|---|---|
| Command | `cask workflow doctor` |
| Entry point | `caskmcp/cli/commands_workflow.py` :: `workflow_doctor` |

---

### CAP-CLI-012: auth

Manage authentication profiles for capture. Profiles store Playwright browser storage state (cookies, localStorage) locally.

| Field | Value |
|---|---|
| Command | `cask auth <subcommand>` |
| CLI file | `caskmcp/cli/main.py` :: `auth` group |
| Implementation | `caskmcp/cli/auth.py` |
| Domain module | `caskmcp/core/auth/profiles.py` :: `AuthProfileManager` |

#### CAP-CLI-012a: auth login

Launch headful browser for one-time login, saving storage state to a named profile.

| Field | Value |
|---|---|
| Command | `cask auth login --profile <NAME> --url <URL>` |
| Entry point | `caskmcp/cli/auth.py` :: `auth_login` |

#### CAP-CLI-012b: auth status

Show the status of an auth profile.

| Field | Value |
|---|---|
| Command | `cask auth status --profile <NAME>` |
| Entry point | `caskmcp/cli/auth.py` :: `auth_status` |

#### CAP-CLI-012c: auth clear

Delete an auth profile.

| Field | Value |
|---|---|
| Command | `cask auth clear --profile <NAME>` |
| Entry point | `caskmcp/cli/auth.py` :: `auth_clear` |

#### CAP-CLI-012d: auth list

List all auth profiles.

| Field | Value |
|---|---|
| Command | `cask auth list` |
| Entry point | `caskmcp/cli/auth.py` :: `auth_list` |

---

## CLI Commands -- Advanced / Hidden

### CAP-CLI-020: compile

Compile captured traffic into contracts, tools manifest, policy, baseline, and toolsets. Low-level building block that `mint` orchestrates.

| Field | Value |
|---|---|
| Command | `cask compile --capture <ID>` |
| CLI file | `caskmcp/cli/main.py` :: `compile` (hidden) |
| Implementation | `caskmcp/cli/compile.py` :: `run_compile` |
| Key options | `--scope`, `--scope-file`, `--format` (manifest, openapi, all), `--output`, `--deterministic` |

---

### CAP-CLI-021: bundle

Create a deterministic toolpack bundle (zip) for distribution.

| Field | Value |
|---|---|
| Command | `cask bundle --toolpack <PATH> --out <ZIP>` |
| CLI file | `caskmcp/cli/main.py` :: `bundle` (hidden) |
| Implementation | `caskmcp/cli/bundle.py` :: `run_bundle` |

---

### CAP-CLI-022: lint

Lint capability artifacts for strict governance hygiene. Validates tool manifests and policy files.

| Field | Value |
|---|---|
| Command | `cask lint --toolpack <PATH>` |
| CLI file | `caskmcp/cli/main.py` :: `lint` (hidden) |
| Implementation | `caskmcp/cli/lint.py` :: `run_lint` |
| Key options | `--tools`, `--policy`, `--format` (text, json) |

---

### CAP-CLI-023: doctor

Validate toolpack readiness for execution.

| Field | Value |
|---|---|
| Command | `cask doctor --toolpack <PATH>` |
| CLI file | `caskmcp/cli/main.py` :: `doctor` (hidden) |
| Implementation | `caskmcp/cli/doctor.py` :: `run_doctor` |
| Key options | `--runtime` (auto, local, container) |

---

### CAP-CLI-024: enforce

Run the policy enforcement gateway (standalone, outside MCP transport).

| Field | Value |
|---|---|
| Command | `cask enforce --tools <PATH> --policy <PATH>` |
| CLI file | `caskmcp/cli/main.py` :: `enforce` (hidden) |
| Implementation | `caskmcp/cli/enforce.py` :: `run_enforce` |
| Key options | `--mode` (evaluate, proxy), `--port`, `--base-url`, `--auth`, `--lockfile`, `--audit-log`, `--dry-run`, `--confirm-store`, `--allow-private-cidr`, `--allow-redirects`, `--unsafe-no-lockfile` |

---

### CAP-CLI-025: migrate

Migrate legacy toolpack/artifact layouts to current schema contracts.

| Field | Value |
|---|---|
| Command | `cask migrate --toolpack <PATH>` |
| CLI file | `caskmcp/cli/main.py` :: `migrate` (hidden) |
| Implementation | `caskmcp/cli/migrate.py` :: `run_migrate` |
| Key options | `--apply` / `--dry-run` |

---

### CAP-CLI-026: inspect

Read-only MCP introspection server. Exposes governance state (list actions, check policy, view approvals, risk summaries) as MCP tools.

| Field | Value |
|---|---|
| Command | `cask inspect --tools <PATH>` |
| CLI file | `caskmcp/cli/commands_mcp.py` :: `inspect` (hidden) |
| Implementation | `caskmcp/mcp/meta_server.py` :: `run_meta_server`, `CaskMCPMetaMCPServer` |
| Exposed tools | `caskmcp_list_actions`, `caskmcp_check_policy`, `caskmcp_get_approval_status`, `caskmcp_list_pending_approvals`, `caskmcp_get_action_details`, `caskmcp_risk_summary` |

---

### CAP-CLI-027: scope merge

Merge suggested scopes into authoritative scopes via explicit proposal.

| Field | Value |
|---|---|
| Command | `cask scope merge` |
| CLI file | `caskmcp/cli/main.py` :: `scope_merge` (hidden) |
| Implementation | `caskmcp/cli/scopes.py` :: `run_scopes_merge` |
| Key options | `--suggested`, `--authoritative`, `--output`, `--apply` |

---

### CAP-CLI-028: confirm

Out-of-band confirmation workflow for state-changing actions at runtime.

| Field | Value |
|---|---|
| Command | `cask confirm <subcommand>` |
| CLI file | `caskmcp/cli/main.py` :: `confirm` group (hidden) |
| Implementation | `caskmcp/cli/confirm.py` |

#### CAP-CLI-028a: confirm grant

Grant a pending confirmation token.

| Field | Value |
|---|---|
| Command | `cask confirm grant <TOKEN_ID>` |
| Entry point | `caskmcp/cli/confirm.py` :: `run_confirm_grant` |

#### CAP-CLI-028b: confirm deny

Deny a pending confirmation token with optional reason.

| Field | Value |
|---|---|
| Command | `cask confirm deny <TOKEN_ID>` |
| Entry point | `caskmcp/cli/confirm.py` :: `run_confirm_deny` |

#### CAP-CLI-028c: confirm list

List all pending confirmation tokens.

| Field | Value |
|---|---|
| Command | `cask confirm list` |
| Entry point | `caskmcp/cli/confirm.py` :: `run_confirm_list` |

---

### CAP-CLI-029: propose

Agent draft proposal workflow for new capabilities.

| Field | Value |
|---|---|
| Command | `cask propose <subcommand>` |
| CLI file | `caskmcp/cli/main.py` :: `propose` group (hidden) |
| Implementation | `caskmcp/cli/propose.py` |
| Domain engine | `caskmcp/core/proposal/engine.py` :: `ProposalEngine` |
| Publisher | `caskmcp/core/proposal/publisher.py` |

#### CAP-CLI-029a: propose create

Generate endpoint catalog and tool proposals from a capture.

| Field | Value |
|---|---|
| Command | `cask propose create <CAPTURE_ID>` |
| Entry point | `caskmcp/cli/propose.py` :: `run_propose_from_capture` |

#### CAP-CLI-029b: propose publish

Publish accepted proposals into runtime-ready bundle artifacts with confidence and risk filtering.

| Field | Value |
|---|---|
| Command | `cask propose publish <PROPOSAL_INPUT>` |
| Entry point | `caskmcp/cli/propose.py` :: `run_propose_publish` |
| Key options | `--min-confidence`, `--max-risk`, `--include-review-required`, `--proposal-id`, `--sync-lockfile` |

#### CAP-CLI-029c: propose list / show / approve / reject

Manage individual proposals.

| Field | Value |
|---|---|
| Commands | `cask propose list`, `cask propose show <ID>`, `cask propose approve <ID>`, `cask propose reject <ID>` |
| Entry points | `caskmcp/cli/propose.py` :: `run_propose_list`, `run_propose_show`, `run_propose_approve`, `run_propose_reject` |

---

### CAP-CLI-030: compliance report

Generate a structured EU AI Act compliance report covering human oversight, tool inventory, risk management, and accuracy monitoring.

| Field | Value |
|---|---|
| Command | `cask compliance report` |
| CLI file | `caskmcp/cli/main.py` :: `compliance_report` (hidden) |
| Implementation | `caskmcp/cli/compliance.py` :: `run_compliance_report` |
| Domain engine | `caskmcp/core/compliance/report.py` :: `ComplianceReporter` |

---

### CAP-CLI-031: state unlock

Clear the root state lock file (recovery tool for stuck locks).

| Field | Value |
|---|---|
| Command | `cask state unlock` |
| CLI file | `caskmcp/cli/main.py` :: `state_unlock` (hidden) |
| Key options | `--force` |

---

## Core Domain -- Capture & Parsing

### CAP-CAPTURE-001: HAR Parsing

Parse HTTP Archive (HAR) files into `CaptureSession` objects.

| Field | Value |
|---|---|
| Module | `caskmcp/core/capture/har_parser.py` |
| Class | `HARParser` |
| Input | `.har` files |
| Output | `CaptureSession` model (`caskmcp/models/capture.py`) |

---

### CAP-CAPTURE-002: OpenTelemetry Parsing

Parse OpenTelemetry trace exports into `CaptureSession` objects.

| Field | Value |
|---|---|
| Module | `caskmcp/core/capture/otel_parser.py` |
| Class | `OTELParser` |
| Input | OTEL JSON trace files |
| Output | `CaptureSession` model |

---

### CAP-CAPTURE-003: OpenAPI Parsing

Parse OpenAPI 3.0/3.1 specifications and convert them into `CaptureSession` objects, bootstrapping tools from existing API documentation.

| Field | Value |
|---|---|
| Module | `caskmcp/core/capture/openapi_parser.py` |
| Class | `OpenAPIParser` |
| Input | OpenAPI `.yaml`/`.json` specs |
| Output | `CaptureSession` model |

---

### CAP-CAPTURE-004: Playwright Browser Capture

Capture HTTP traffic using Playwright browser automation. Records network requests/responses during interactive browser sessions. Supports interactive, timed headless, and scripted automation modes. In-flight exchange creation tasks are tracked and awaited before browser close to prevent dropped captures.

| Field | Value |
|---|---|
| Module | `caskmcp/core/capture/playwright_capture.py` |
| Class | `PlaywrightCapture` |
| Modes | Interactive (headful), headless (timed), scripted (`async run(page, context)`) |
| Task tracking | `_pending_tasks` list — all async exchange tasks are gathered before `browser.close()` |
| Output | `CaptureSession` model |

---

### CAP-CAPTURE-005: WebMCP Discovery

Discover tools declared by websites via W3C WebMCP (`navigator.modelContext`), MCP-B polyfill, HTML meta tags, and `.well-known/mcp-tools.json`.

| Field | Value |
|---|---|
| Module | `caskmcp/core/capture/webmcp_capture.py` |
| Model | `WebMCPTool` |
| Supported protocols | W3C WebMCP (`provideContext`, `registerTool`), MCP-B polyfill (`window.__MCP_B_TOOLS__`), HTML meta/link tags, `.well-known/mcp-tools.json` |

---

### CAP-CAPTURE-006: Path Blocklist

Filter out noise paths (health checks, static assets, internal framework routes) during capture.

| Field | Value |
|---|---|
| Module | `caskmcp/core/capture/path_blocklist.py` |

---

## Core Domain -- Normalization

### CAP-NORM-001: Path Normalization

Normalize observed URL paths by collapsing path parameters into `{param}` placeholders, detecting numeric IDs, UUIDs, and other patterns.

| Field | Value |
|---|---|
| Module | `caskmcp/core/normalize/path_normalizer.py` |
| Class | `PathNormalizer` |

---

### CAP-NORM-002: Endpoint Aggregation

Aggregate multiple HTTP exchanges at the same normalized path into a single `Endpoint` with merged schemas, parameters, and metadata.

| Field | Value |
|---|---|
| Module | `caskmcp/core/normalize/aggregator.py` |
| Class | `EndpointAggregator` |
| Output | `Endpoint` model (`caskmcp/models/endpoint.py`) |

---

### CAP-NORM-003: Flow Detection

Detect data dependencies between endpoints by analyzing which response fields feed into other endpoints' request parameters. Produces a `FlowGraph` with edges linking dependent tools.

| Field | Value |
|---|---|
| Module | `caskmcp/core/normalize/flow_detector.py` |
| Class | `FlowDetector` |
| Output | `FlowGraph` model (`caskmcp/models/flow.py`) |

---

### CAP-NORM-004: Domain Tagging

Tag endpoints with domain-specific labels (auth, commerce, users, admin, etc.) from path analysis.

| Field | Value |
|---|---|
| Module | `caskmcp/core/normalize/tagger.py` |

---

## Core Domain -- Compilation

### CAP-COMPILE-001: Tool Manifest Generation

Compile normalized endpoints into agent-consumable tool manifests with JSON Schema input/output, risk-tier-based confirmation/rate limits, flow metadata (`depends_on`/`enables`), and agent-friendly descriptions. Supports GraphQL operation splitting.

| Field | Value |
|---|---|
| Module | `caskmcp/core/compile/tools.py` |
| Class | `ToolManifestGenerator` |
| Output | `tools.json` -- array of actions with `id`, `tool_id`, `signature_id`, `method`, `path`, `host`, `input_schema`, `output_schema`, `risk_tier`, `confirmation_required`, `rate_limit_per_minute`, `tags` |

---

### CAP-COMPILE-002: Policy Generation

Generate default enforcement policies from endpoints including allow/deny/confirm/budget/audit/redact rules, admin endpoint blocking, PII protection, and auth auditing.

| Field | Value |
|---|---|
| Module | `caskmcp/core/compile/policy.py` |
| Class | `PolicyGenerator` |
| Output | `policy.yaml` with rules sorted by priority, default-deny, global rate limits, redaction headers/patterns |

---

### CAP-COMPILE-003: Contract Compilation (OpenAPI 3.1)

Compile endpoints into an OpenAPI 3.1 specification serving as the API contract.

| Field | Value |
|---|---|
| Module | `caskmcp/core/compile/contract.py` |
| Class | `ContractCompiler` |
| Output | `contracts.yaml` (OpenAPI 3.1) |

---

### CAP-COMPILE-004: Baseline Generation

Generate baseline snapshots from endpoints for future drift detection.

| Field | Value |
|---|---|
| Module | `caskmcp/core/compile/baseline.py` |
| Class | `BaselineGenerator` |
| Output | `baseline.json` with endpoint parameter/schema/auth/risk snapshots |

---

### CAP-COMPILE-005: Toolset Generation

Generate named toolsets (readonly, readwrite, all) from a compiled tools manifest. Toolsets partition actions by HTTP method and GraphQL operation type.

| Field | Value |
|---|---|
| Module | `caskmcp/core/compile/toolsets.py` |
| Class | `ToolsetGenerator` |
| Output | `toolsets.yaml` with named action lists, default toolset metadata |

---

## Core Domain -- Scope Filtering

### CAP-SCOPE-001: Scope Engine

Filter endpoints by scope rules. Supports built-in scopes (`first_party_only`, `agent_safe_readonly`) and custom YAML scope files.

| Field | Value |
|---|---|
| Module | `caskmcp/core/scope/engine.py` |
| Class | `ScopeEngine` |
| Built-in scopes | `caskmcp/core/scope/builtins.py` :: `get_builtin_scope` |
| Parser | `caskmcp/core/scope/parser.py` :: `parse_scope_file` |
| Inference | `caskmcp/core/scope/inference.py` |
| Scope model | `caskmcp/models/scope.py` :: `Scope`, `ScopeType` |

---

## Core Domain -- Approval & Signing

### CAP-APPROVE-001: Ed25519 Approval Signing

Sign and verify tool approvals using local Ed25519 keypairs. Auto-generates keypairs on first use. Maintains a trust store of active/revoked signing keys with signer identity binding.

| Field | Value |
|---|---|
| Module | `caskmcp/core/approval/signing.py` |
| Class | `ApprovalSigner` |
| Key management | Auto-generate, rotate (`rotate_key`), revoke (`revoke_key`) |
| Key storage | `<root>/state/keys/` (`approval_ed25519_private.pem`, `approval_ed25519_public.pem`, `trusted_signers.json`) |
| Signature format | `ed25519:<key_id>:<base64url_signature>` |
| Approver allowlist | `CASKMCP_APPROVERS` env var |
| Helpers | `resolve_approval_root`, `resolve_approver` |

---

### CAP-APPROVE-002: Lockfile Management

Manage the lockfile (`caskmcp.lock.yaml`) that tracks tool approval statuses (pending, approved, rejected) with cryptographic signatures and artifact integrity digests.

| Field | Value |
|---|---|
| Module | `caskmcp/core/approval/lockfile.py` (grep: `LockfileManager`, `ToolApproval`, `ApprovalStatus`) |
| Integrity digests | `caskmcp/core/approval/integrity.py` :: `compute_artifacts_digest`, `compute_artifacts_digest_from_paths` |
| Snapshot | `caskmcp/core/approval/snapshot.py` |
| Canonical hashing | `caskmcp/utils/canonical.py` :: `canonical_digest`, `canonicalize_tools_manifest`, `canonicalize_policy`, `canonicalize_toolsets` |

---

## Core Domain -- Drift Detection

### CAP-DRIFT-001: Drift Engine

Compare two endpoint sets or an endpoint set against a baseline to detect breaking changes, auth changes, risk escalations, schema drift, parameter changes, and flow-aware broken dependencies.

| Field | Value |
|---|---|
| Module | `caskmcp/core/drift/engine.py` |
| Class | `DriftEngine` |
| Methods | `compare` (capture-to-capture), `compare_to_baseline` |
| Drift types | `BREAKING`, `AUTH`, `RISK`, `ADDITIVE`, `SCHEMA`, `PARAMETER`, `UNKNOWN` |
| Severity levels | `CRITICAL`, `ERROR`, `WARNING`, `INFO` |
| Output model | `caskmcp/models/drift.py` :: `DriftReport`, `DriftItem` |
| Exit codes | 0 (clean), 1 (risk changes), 2 (breaking changes) |

---

## Core Domain -- Repair

### CAP-REPAIR-001: Repair Engine

Diagnose toolpack issues from audit logs, drift reports, and verify reports. Propose copy-pasteable remediation commands classified by safety level (SAFE / APPROVAL_REQUIRED / MANUAL). Never auto-executes — outputs commands for human review.

| Field | Value |
|---|---|
| Module | `caskmcp/core/repair/engine.py` |
| Class | `RepairEngine` |
| Methods | `run(context_paths, auto_discover)` |
| Models | `caskmcp/models/repair.py` :: `RepairReport`, `DiagnosisItem`, `PatchItem`, `PatchKind`, `PatchAction` |
| Safety model | `SAFE` (zero capability expansion), `APPROVAL_REQUIRED` (changes state), `MANUAL` (requires investigation) |
| Diagnosis sources | Audit JSONL (DENY entries), drift reports (actionable types), verify reports (fail/unknown sections) |
| Patch actions | `gate_allow`, `gate_sync`, `gate_reseal`, `verify_contracts`, `verify_provenance`, `investigate`, `re_mint`, `review_policy`, `add_host` |
| Redaction | Strips Authorization, Cookie, API key headers from all evidence before output |
| Exit codes | 0 (healthy), 1 (report generated), 2 (CLI error) |
| Schema version | `0.1` |

---

### CAP-REPAIR-002: Repair CLI

CLI entry point for repair. Reads toolpack, parses context files, writes structured output artifacts.

| Field | Value |
|---|---|
| Module | `caskmcp/cli/repair.py` |
| Function | `run_repair()` |
| CLI command | `cask repair --toolpack <path> [--from <context>...] [-o <dir>] [--no-auto-discover]` |
| Outputs | `repair.json`, `repair.md`, `diagnosis.json`, `patch.commands.sh` |
| Default output | `<root>/repairs/<YYYYMMDD_HHMMSSZ>_repair/` |
| Flags | `--from` (repeatable), `--auto-discover/--no-auto-discover`, `--output/-o` |

---

## Core Domain -- Policy Enforcement

### CAP-ENFORCE-001: Policy Engine

Evaluate requests against policy rules (allow, deny, confirm, budget, audit, redact) with priority-based matching, host/path/method/risk-tier/scope conditions, and sliding-window budget tracking.

| Field | Value |
|---|---|
| Module | `caskmcp/core/enforce/engine.py` |
| Class | `PolicyEngine` |
| Budget tracking | `caskmcp/core/enforce/engine.py` :: `BudgetTracker` (per-minute and per-hour windows) |
| Policy model | `caskmcp/models/policy.py` :: `Policy`, `PolicyRule`, `MatchCondition`, `RuleType`, `EvaluationResult` |

---

### CAP-ENFORCE-002: Decision Engine

Shared decision engine for enforce gateway and MCP runtime. Evaluates lockfile approval status, artifact integrity digest verification, confirmation requirements, and network safety (private CIDR blocking, redirect validation).

| Field | Value |
|---|---|
| Module | `caskmcp/core/enforce/decision_engine.py` |
| Class | `DecisionEngine` |
| Decision types | `ALLOW`, `DENY`, `CONFIRM` |
| Reason codes | `caskmcp/models/decision.py` :: `ReasonCode` (e.g. `DENIED_UNKNOWN_ACTION`, `DENIED_INTEGRITY_MISMATCH`, `DENIED_NOT_APPROVED`) |
| Network safety | `caskmcp/models/decision.py` :: `NetworkSafetyConfig` |

---

### CAP-ENFORCE-003: Confirmation Store

SQLite-backed out-of-band confirmation challenge store for runtime step-up approvals. Issues HMAC-signed tokens, tracks grant/deny decisions with TTL.

| Field | Value |
|---|---|
| Module | `caskmcp/core/enforce/confirmation_store.py` |
| Class | `ConfirmationStore` |
| Storage | SQLite at `<root>/state/confirmations.db` |
| Token format | `cfrmv1:...` with HMAC signing |
| Signing key | `<root>/state/confirmation_signing.key` |

---

## Core Domain -- Verification

### CAP-VERIFY-001: Contract Validation

Validate toolpack artifacts against their OpenAPI contract schemas.

| Field | Value |
|---|---|
| Module | `caskmcp/core/verify/contracts.py` |
| Functions | `load_contracts`, `validate_contract_file` |

---

### CAP-VERIFY-002: Deterministic Replay

Replay captured traffic against compiled tools to verify parity.

| Field | Value |
|---|---|
| Module | `caskmcp/core/verify/replay.py` |
| Function | `run_replay` |

---

### CAP-VERIFY-003: Outcomes Verification

Verify that tool invocations produce expected outcomes using playbooks and UI assertions.

| Field | Value |
|---|---|
| Module | `caskmcp/core/verify/outcomes.py` |
| Function | `run_outcomes` |

---

### CAP-VERIFY-004: Provenance Scoring

Score provenance confidence: how well each UI assertion maps to an observed API action, with configurable top-k and unknown-budget thresholds.

| Field | Value |
|---|---|
| Module | `caskmcp/core/verify/provenance.py` |
| Function | `run_provenance` |

---

### CAP-VERIFY-005: Evidence Bundles

Create and persist evidence bundles from verification runs.

| Field | Value |
|---|---|
| Module | `caskmcp/core/verify/evidence.py` |
| Functions | `create_evidence_bundle`, `create_evidence_entry`, `save_evidence_bundle` |
| Model | `caskmcp/models/verify.py` :: `EvidenceBundle`, `VerifyReport`, `VerifyStatus` |

---

## Core Domain -- MCP Server

### CAP-MCP-001: Governed MCP Server (stdio)

Full MCP server on stdio transport exposing compiled tools as callable actions. Routes invocations through the DecisionEngine (lockfile approval, policy enforcement, confirmation, budget tracking), proxies approved requests to upstream APIs, and logs all decisions.

| Field | Value |
|---|---|
| Module | `caskmcp/mcp/server.py` |
| Class | `CaskMCPMCPServer` |
| Transport | stdio (via `mcp` SDK) |
| Features | Lockfile integrity gating, per-tool approval enforcement, policy evaluation, out-of-band confirmation, rate limiting, audit logging, dry-run mode, private CIDR blocking, redirect validation, Next.js build-ID resolution |

---

### CAP-MCP-002: Meta/Introspection MCP Server

Read-only MCP server exposing governance state inspection tools for operators and CI.

| Field | Value |
|---|---|
| Module | `caskmcp/mcp/meta_server.py` |
| Class | `CaskMCPMetaMCPServer` |
| Exposed tools | `caskmcp_list_actions`, `caskmcp_check_policy`, `caskmcp_get_approval_status`, `caskmcp_list_pending_approvals`, `caskmcp_get_action_details`, `caskmcp_risk_summary` |

---

### CAP-MCP-003: Toolpack Resolution

Load and resolve all artifact paths from a `toolpack.yaml` manifest including tools, policy, toolsets, contracts, baseline, lockfile, and container runtime configuration.

| Field | Value |
|---|---|
| Module | `caskmcp/core/toolpack.py` |
| Models | `ToolpackRuntime`, `ToolpackContainerRuntime`, `ToolpackOrigin`, `ToolpackPaths` |

---

## Core Domain -- Proposals

### CAP-PROPOSE-001: Proposal Engine

Create, list, review, and promote agent draft proposals for new capabilities. Proposals are stored under `<root>/drafts/` and only the approve command can promote them.

| Field | Value |
|---|---|
| Module | `caskmcp/core/proposal/engine.py` |
| Class | `ProposalEngine` |
| Model | `caskmcp/models/proposal.py` :: `DraftProposal`, `MissingCapability`, `ProposalStatus` |

---

### CAP-PROPOSE-002: Proposal Publisher

Publish accepted proposals into runtime-ready bundle artifacts with confidence/risk filtering and optional lockfile sync.

| Field | Value |
|---|---|
| Module | `caskmcp/core/proposal/publisher.py` |

---

## System Responsibilities

### CAP-SYS-001: Redaction

Strip sensitive data (cookies, tokens, auth headers, API keys, JWTs, passwords, PII) from captured traffic by default. Supports configurable redaction profiles, body truncation with SHA-256 digests, and schema-zero sampling for oversized payloads.

| Field | Value |
|---|---|
| Module | `caskmcp/core/capture/redactor.py` |
| Class | `Redactor` |
| Profiles module | `caskmcp/core/capture/redaction_profiles.py` |
| Built-in profiles | `default_safe`, `high_risk_pii` |
| Profile model | `RedactionProfile` (configurable headers, query params, body patterns, max body chars) |
| Targets | Headers, URL query params, request/response bodies (regex), JSON dict keys |

---

### CAP-SYS-002: Audit Logging

Log every capture, compile, drift, enforce decision, confirmation, budget, and block event. Supports file-based (JSONL) and in-memory backends.

| Field | Value |
|---|---|
| Module | `caskmcp/core/audit/logger.py` |
| Class | `AuditLogger` |
| Backends | `FileAuditBackend` (JSONL), `MemoryAuditBackend` (testing) |
| Event types | `capture_started`, `capture_completed`, `compile_started`, `compile_completed`, `drift_detected`, `enforce_decision`, `confirmation_requested`, `confirmation_granted`, `confirmation_denied`, `budget_exceeded`, `request_blocked` |
| Decision traces | `caskmcp/core/audit/decision_trace.py` :: `DecisionTraceEmitter` |

---

### CAP-SYS-003: State Management

Local filesystem storage for captures, artifacts, toolpacks, baselines, reports, evidence, scopes, and state. Root-level command locking prevents concurrent mutations.

| Field | Value |
|---|---|
| Storage module | `caskmcp/storage/filesystem.py` :: `Storage` |
| Directory structure | `<root>/captures/`, `<root>/artifacts/`, `<root>/toolpacks/`, `<root>/baselines/`, `<root>/reports/`, `<root>/evidence/`, `<root>/scopes/`, `<root>/state/` |
| Lock module | `caskmcp/utils/locks.py` :: `root_command_lock`, `clear_root_lock`, `RootLockError` |
| State resolution | `caskmcp/utils/state.py` :: `resolve_root`, `confirmation_store_path`, `runtime_lock_path` |

---

### CAP-SYS-004: Container Runtime

Emit Dockerfile, entrypoint, requirements, and run wrapper for containerized toolpack execution. Supports build and push via Docker CLI.

| Field | Value |
|---|---|
| Module | `caskmcp/core/runtime/container.py` |
| Function | `emit_container_runtime` |
| Output | `ContainerRuntimeFiles` (Dockerfile, entrypoint.sh, caskmcp.run, requirements.lock) |
| Default base image | `python:3.11-slim` |

---

### CAP-SYS-005: LLM Enrichment (Optional)

Optional post-compile enrichment pass using an OpenAI-compatible LLM endpoint. Provides richer tags, descriptions, and "when to use" guidance for endpoints. No LLM SDK dependency -- uses httpx directly.

| Field | Value |
|---|---|
| Module | `caskmcp/core/enrich/llm_classifier.py` |
| Class | `LLMEnricher` |

---

### CAP-SYS-006: Schema Versioning

Track and migrate artifact schema versions across the project.

| Field | Value |
|---|---|
| Module | `caskmcp/utils/schema_version.py` |
| Constants | `CURRENT_SCHEMA_VERSION` |
| Functions | `resolve_schema_version`, `resolve_generated_at` |

---

### CAP-SYS-007: Canonical Digests

Deterministic hashing of artifacts for integrity verification and lockfile sealing.

| Field | Value |
|---|---|
| Module | `caskmcp/utils/canonical.py` |
| Functions | `canonical_digest`, `canonicalize`, `canonicalize_tools_manifest`, `canonicalize_policy`, `canonicalize_toolsets`, `canonical_request_digest` |
| Digest module | `caskmcp/utils/digests.py` |

---

### CAP-SYS-008: Tool Naming

Generate unique, human-readable tool names from HTTP method + path and resolve collisions with host-scoped suffixes.

| Field | Value |
|---|---|
| Module | `caskmcp/utils/naming.py` |
| Functions | `generate_tool_name`, `resolve_collision` |
