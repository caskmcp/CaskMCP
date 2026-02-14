# Security Policy

## Reporting a Vulnerability

Please report security issues privately.

Preferred path:
- Use GitHub Security Advisories for this repository ("Report a vulnerability").

If private reporting is unavailable, open a GitHub issue with minimal details
and request a private follow-up channel. Do not post exploit details, tokens,
or sensitive traces publicly.

## Scope

CaskMCP is intended for first-party or explicitly authorized capture/enforcement
workflows. Security reports are prioritized for:
- Capture redaction behavior
- Policy enforcement bypasses
- Approval/lockfile integrity bypasses
- SSRF or network-safety bypasses in proxy mode

## Supported Versions

This project is currently in beta (v0.2.0b1). Security fixes are applied to the
latest release line on `main`.
