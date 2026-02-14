# CaskMCP Strategy & Roadmap

**Status:** Strategic North Star (Living Document)
**Last Updated:** 2026-02-08

## Canonical Direction

- Current feature status: see `README.md` Feature Status table.
- Canonical architecture: `ARCHITECTURE.md`
- This document translates that direction into positioning, sequencing, and execution choices.

## Strategic Thesis

CaskMCP wins by being the **build-time governance layer** for agent capabilities:

1. capture/import real behavior
2. compile deterministic artifacts
3. require explicit approvals for expansion
4. gate drift in CI before deployment

This differentiates CaskMCP from runtime-first gateway products.

## Positioning

### External Hook

"Traffic-to-toolpack compiler for safe agent actions."

### Architectural Truth

"Deterministic artifact pipeline for governable agent tool surfaces."

## Product Shape

### Current shipped path

- `caskmcp mint`
- `caskmcp approve`
- `caskmcp run`
- `caskmcp plan` (deterministic diff-style review report)
- `caskmcp drift` (CI gate)

### vNext terminology alignment

- vNext docs use `diff` language; current shipped command is `plan`
- current `caskmcp mcp meta` maps to control-plane introspection framing

## Hard Constraints

- no agent-led approvals
- no agent privilege self-expansion
- no "proof of correctness" claims
- no runtime-gateway positioning as primary product story

## Roadmap

### Phase 1: Core Wedge (Now)

- tighten docs around one Golden Path
- keep shipped/planned matrix explicit
- standardize control-plane language for `mcp meta`
- document scopes rigorously (`docs/scopes.md`)

### Phase 2: Verification Contracts

- introduce contract-first verification artifacts
- produce reproducible evidence bundles
- add reliable CI gating around contract failures

### Phase 3: Drift + Governance Maturity

- classify broadening vs narrowing drift
- enforce explicit approvals for broadening changes
- improve approval review ergonomics and signing metadata

### Phase 4: Optional Platform Extensions

- richer control-plane APIs for operators/CI
- packaging and distribution hardening
- optional integrations with downstream runtime gateways

## Differentiation

CaskMCP focuses on **artifact generation and governance readiness**.

- Runtime gateways enforce what already exists.
- CaskMCP compiles what should exist, with reviewable diffs and approvals.

## Competitor Spectrum

- Spec-to-code generators: generate from static specs
- Runtime gateways/proxies: enforce existing tool surfaces
- Static drift scanners: report changes in existing systems

CaskMCP's wedge is the pipeline from observed behavior to governable artifacts.

## Compliance Positioning

CaskMCP should be described as producing controls and evidence for audit readiness.

- good claim: "audit-ready evidence and governance controls"
- avoid claim: "turnkey legal compliance"

Not legal advice: users should validate obligations with counsel.

## GTM Priorities

1. reduce onboarding friction (`demo`, `mint`)
2. prove governance loop (`approve`, `plan`, `drift`)
3. show CI integration and reproducibility
4. keep docs honest about shipped vs planned

## External Signals

- [Runlayer funding announcement](https://www.runlayer.com/blog/runlayer-raises-11m-to-scale-enterprise-mcp-infrastructure)
- [MCP Registry preview](https://blog.modelcontextprotocol.io/posts/2025-09-08-mcp-registry-preview/)
