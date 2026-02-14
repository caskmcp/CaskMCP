# CaskMCP v1 Release Plan

> See `README.md` Feature Status table for what's shipped vs planned.

This is the execution lock for v1.

## v1 outcome

Ship the deterministic governance wedge end-to-end:

`mint -> diff -> gate -> run -> drift -> verify`

## Public command surface

Flagship:

- `mint`, `diff`, `gate`, `run`, `drift`, `verify`, `mcp serve`, `mcp inspect`

Compatibility aliases:

- `plan -> diff`
- `approve -> gate`
- `mcp meta -> mcp inspect`

Advanced shipped commands are hidden from default help and available via `--help-all`.

## Locked contracts (release gates)

### Governance and safety

- [x] Runtime fail-closed lockfile behavior with approved lockfile search order.
- [x] Ed25519 approval signatures with signer identity, key id, reason, timestamp, and `1-of-1` mode.
- [x] Key trust store location and revoke/rotate capabilities.
- [x] Root-level state lock (`<root>/state/lock`) for mutating commands.
- [x] Runtime network safety: scheme restrictions, DNS/IP checks, redirect-hop validation.
- [x] App/IdP host separation (`allowed_hosts.app`, `allowed_hosts.idp`).
- [x] Confirmation token replay protection and strict request binding.
- [x] DecisionTrace JSONL emission with required schema fields.

### Artifact and scope model

- [x] `contracts.yaml` artifact with versioned schema + legacy contract compatibility.
- [x] `coverage_report.json` emission in compile output.
- [x] Suggested vs authoritative scope ownership (`scopes.suggested.yaml`, `scopes.yaml`).
- [x] `scopes merge` explicit proposal workflow.
- [x] `migrate` command for minimal artifact/version migration.

### Verification and CI

- [x] `verify` modes include provenance.
- [x] Playbook and UI assertion schema validation.
- [x] `diff --format github-md` with tests.
- [x] GitHub composite gate action (`.github/actions/caskmcp-gate/action.yml`).
- [x] `lint` gate for guardrails + regex/override justifications.

### Documentation truth

- [x] README and user guide aligned with shipped CLI.
- [x] New v1 spec docs for playbook/verification/redaction/CI policies.
- [x] Explicit known limitations and threat-model boundaries.

## Exit criteria

1. `python -m pytest tests/ -v` passes in CI.
2. No shipped claim exists without corresponding CLI behavior and tests.
3. Golden path is copy/paste from docs on a clean machine.
4. Runtime blocks unapproved or signature-invalid actions by default.
