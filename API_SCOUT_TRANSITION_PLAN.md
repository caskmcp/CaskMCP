## Project Summary: **Actionforge**

**Actionforge** is an open-core “action surface compiler” that turns observed web/API behavior into **safe, versioned, agent-ready tools (MCP servers)** with **drift detection** and **enforcement guardrails**.

It is a refactor and reframe of the current API Scout repo. We are not building a recon framework. We are building a **behavior → contract → tools → policy** pipeline.

ORIGINAL API SCOUT REPO IS LOCATED AT: /Users/thomasallicino/Documents/api-recon
Feel free to do all the copying you need from it, and refactoring, etc.
The first thing you should do is get a comprehensive understanding of the API Scout/API Recon project I made.

---

# 1) What Actionforge is

Actionforge converts **real traffic** (captured via Playwright/HAR/proxy) into four durable artifacts:

1. **Contract**

* An OpenAPI-style spec derived from observed requests and responses.
* Stable endpoint IDs and normalized schemas.

2. **Tool Surface**

* A curated set of named “actions” designed for tool-calling agents.
* Each action has strict input/output schemas and a risk tier.

3. **Policy**

* Enforceable allowlists, confirmation rules, budgets, and redaction rules.
* Designed to make agent usage safe by default.

4. **Drift Reports**

* Structured diff between runs (or between observed behavior and an existing spec).
* Drift is classified by risk and can trigger alerts or blocks.

Actionforge’s killer feature is your current “focus mode,” elevated into a first-class abstraction called **Scopes**.

---

# 2) The core problem we solve

Modern systems have three reality gaps:

## Gap A: “Docs lie”

Specs and docs drift from what production actually does. Teams stop trusting contracts.

**Actionforge solves this** by generating contracts from behavior, continuously.

## Gap B: “Tool surfaces are unsafe”

Agents and automation need tools with strict schemas and guardrails. Most real systems do not have them.

**Actionforge solves this** by compiling a safe, minimal, allowlisted tool surface.

## Gap C: “Change is silent”

Breaking changes and risky new behavior show up as subtle runtime drift.

**Actionforge solves this** by detecting and classifying drift, then enforcing “block on unknown” policies when needed.

---

# 3) Primary users and why they care

## Platform / DevEx teams

* Want reliable internal API catalogs and contracts.
* Want CI checks to prevent breaking changes.
* Want faster onboarding and fewer integration incidents.

## AI agent builders and AI platform teams

* Want to convert brittle UI workflows into stable tool calls.
* Want to restrict agent actions to a safe subset of endpoints.
* Want auditability for every tool call.

## AppSec / security engineering (secondary buyer)

* Want visibility into real API surfaces and auth flows.
* Want “shadow endpoint” detection from runtime.
* Want risk-based reporting without deploying a heavy enterprise suite.

---

# 4) What makes it “Actionforge” (the differentiator)

Actionforge is not “API discovery.” It is a **compiler**.

### Input

Traffic + policies.

### Output

A safe, versioned action surface and enforceable guardrails.

This is the bridge from:

* “Agent clicks UI and hopes”
  to
* “Agent calls typed tools with policy enforcement”

---

# 5) Product pillars

## Pillar 1: Capture

Supported capture inputs (in priority order):

* **HAR** files (browser captures)
* **Playwright trace / network logs** (preferred for repeatability)
* Optional: a local proxy mode (advanced)

Requirements:

* Deterministic parsing
* Session safety: never persist raw cookies/tokens unless explicitly allowed
* Redaction pass before storage by default

## Pillar 2: Normalize

Normalize traffic into a stable internal representation:

**RequestEvent**

* timestamp
* host, path, method
* headers (redacted)
* query params
* body (redacted and optionally schema inferred)
* response status, headers (redacted), body sample (redacted)
* correlation keys (trace id if present)
* auth indicators (cookie, bearer, oauth flow hints)

Then:

* endpoint clustering (path templating like `/users/{id}`)
* param inference (path params, query params, json body fields)
* response shape inference (best-effort schema generation)

## Pillar 3: Compile into artifacts

For a given capture (or capture window) and scope policy:

### Artifact A: Contract (OpenAPI+)

* OpenAPI 3.0/3.1 output
* Stable endpoint IDs (hash of normalized method + templated path + host scope)
* Schema inference with confidence scores
* Examples with redaction

### Artifact B: Tool Manifest

A tool manifest describes agent-callable actions:

* tool name
* description
* input schema (JSON Schema)
* output schema
* risk tier
* required confirmations
* rate limits / budgets
* allowed hosts/methods/path patterns

This manifest is designed to be easy to map into MCP tools.

### Artifact C: Policy

Machine-enforceable policy definitions:

* allowlist: hosts, methods, path patterns
* denylist: third-party hosts, sensitive endpoints
* confirmation rules: “state-changing requires confirm”
* budgets: calls/min, writes/min, max payload sizes
* redaction rules: header fields, token patterns, PII patterns
* storage rules: retention, scrub levels
* audit rules: required logging fields

### Artifact D: Drift Report

Compare:

* run vs run
* or observed behavior vs a baseline spec

Classify drift:

* **Breaking drift**: response schema change, status code changes, removed endpoints
* **Auth drift**: new auth header, cookie changes, token refresh pattern changes
* **Risk drift**: new state-changing endpoint, new sensitive fields, new host
* **Additive drift**: new endpoints that are read-only
* **Unknown drift**: unclassified changes (default to block for agents)

Output includes:

* human-friendly summary
* structured JSON for CI and alert routing

## Pillar 4: Enforce (Agent Firewall mode)

Actionforge can operate as a gate in front of tools:

* evaluate every proposed call against policy
* if outside allowlist: block
* if risky: require human confirmation token
* enforce budgets and rate limits
* log every attempt with full provenance

This is how you turn tool specs into safety.

---

# 6) Scopes: the “focus mode” that becomes the product core

Rename “focus mode” to **Scopes**.

A Scope is a named policy that:

* selects which traffic becomes part of the tool surface
* defines risk classification
* defines enforcement requirements
* defines what drift matters

### Built-in Scopes (v1)

1. **first_party_only**

* include only requests to configured first-party domains
* drop analytics/CDN/third-party by default

2. **auth_surface**

* endpoints involved in login, token issuance, refresh, session cookies

3. **state_changing**

* heuristic: non-GET methods, or endpoints that change server state
* default “confirm required”

4. **pii_surface** (heuristic)

* endpoints returning or accepting likely PII fields (email, phone, ssn-like patterns)
* stronger redaction and retention rules

5. **agent_safe_readonly**

* strict read-only subset with tight budgets
* suitable as the default tool surface for agents

Scopes are how people will adopt it:

* “Generate the auth surface tools”
* “Monitor drift on state-changing endpoints”
* “Allow agents only the agent_safe_readonly scope”

---

# 7) CLI and developer workflow

## CLI commands (proposed)

### `actionforge capture`

* Runs Playwright capture (or imports)
* Output: `captures/<capture_id>/raw.har` + normalized events

### `actionforge compile`

* `--capture <id>`
* `--scope <scope_name>`
* Outputs: contract, tool manifest, policy, baseline snapshot

### `actionforge drift`

* `--from <capture_id_or_baseline>`
* `--to <capture_id>`
* Outputs: drift.json + drift.md summary
* Exit codes: non-zero on breaking/risk drift for CI gating

### `actionforge serve`

* Local dashboard for browsing surfaces and drift
* Optional, can remain a later phase

### `actionforge enforce`

* Run as a local gateway for tool calls
* Reads: tool manifest + policy
* Logs: audit events

## CI use cases

* Generate contract on every build for key services
* Compare against baseline
* Fail on breaking drift
* Require manual approval for risk drift

---

# 8) Safety and trust: non-negotiable defaults

These defaults are what keep the project credible and broadly adoptable:

1. **Allowlist required**

* Any capture or enforcement that touches networked targets requires explicit allowed hosts.

2. **First-party only by default**

* Third-party requests excluded unless explicitly included.

3. **Redaction on by default**

* Remove cookies, authorization headers, common token patterns.
* Optional enhanced PII redaction.

4. **State-changing requires confirmation**

* Default: POST/PUT/PATCH/DELETE require human confirmation token.

5. **Audit logging always on**

* Every compile, drift, enforce decision is logged.

6. **No “bypass” language or features in core**

* Anything that looks like bypassing protections does not belong in the mainline product.

---

# 9) Architecture and components

## Core modules

1. **Capture Adapters**

* HAR parser
* Playwright adapter
* optional proxy adapter

2. **Normalizer**

* request/response canonicalization
* templating and clustering
* schema inference

3. **Scope Engine**

* policy DSL
* selection filters
* risk classification rules

4. **Compiler**

* OpenAPI generator
* Tool manifest generator
* Policy generator

5. **Drift Engine**

* diffing and classification
* CI-friendly outputs

6. **Enforcer**

* runtime gate for tool calls
* budgets, confirmations, allowlists
* audit log writer

7. **Storage**

* local filesystem store initially
* optional SQLite
* optional later: Postgres + object storage for SaaS

---

# 10) What we keep from API Scout, what we change

## Keep (core value)

* Traffic capture and parsing
* Endpoint extraction and grouping
* Auth flow insight
* Focus mode concept
* Any MCP integration scaffolding (reframed to tool surfaces and guardrails)

## Change (to align with Actionforge)

* Replace “recon” framing with compiler framing
* Replace feature names that imply offensive use
* Move OSINT/fuzzing/mobile reverse engineering to optional plugins (if they exist at all) and do not ship them as defaults
* Move “security_test” into policy checks, boundary checks, and drift risk detection

---

# 11) Milestones and roadmap

## Milestone 1: Action Surface Compiler MVP (2–4 weeks)

* HAR ingest
* Scope engine with 5 presets
* OpenAPI generator
* Tool manifest generator
* Basic drift report (new/removed/changed endpoints)
* Safe defaults enforced in CLI

Deliverable: 60–90 second demo from capture → compile → tools.

## Milestone 2: Drift that matters (2–4 weeks)

* Schema-level drift detection
* Auth drift detection
* Risk drift classification
* CI integration and exit codes
* Slack webhook alerts

## Milestone 3: Enforcement mode (3–6 weeks)

* Policy gate for tool calls
* Confirmation workflow
* Budgets and rate limiting
* Audit log viewer

## Milestone 4: Team product (optional)

* dashboard UI
* RBAC/SSO
* persistent baselines
* hosted or self-hosted “enterprise bundle”

---

# 12) Distribution and “people flock to it” plan

## OSS value loop

* Ship a clean OSS core: compile, scopes, drift.
* Provide templates: GitHub Actions workflows, sample configs.
* Provide a demo app and demo capture so anyone can run it in 2 minutes.

## The hook that spreads

“Turn a messy web app into safe agent tools in under 5 minutes.”

That gets shared in AI circles and DevEx circles.

---

# 13) Monetization path (optional but real)

If you want revenue quickly:

1. Offer a paid “Drift + Agent Safety Assessment”

* You install Actionforge, generate artifacts, deliver a drift/risk report.

2. Convert to subscription

* Continuous drift monitoring
* Alerts
* Team dashboard
* Enterprise policy packs

Open-core keeps adoption friction low.

---

# 14) Definition of done for v1

Actionforge v1 is “done” when:

* You can take a HAR or Playwright capture and reliably produce:

  * scoped OpenAPI spec
  * tool manifest with schemas and risk tiers
  * enforceable policy file
  * drift report against a baseline
* Safe defaults are on and cannot be bypassed accidentally.
* A demo clearly shows: compile scope → agent tool surface → block outside policy → drift alert.