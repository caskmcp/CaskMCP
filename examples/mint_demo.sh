#!/usr/bin/env bash
# CaskMCP Mint Demo
#
# One command to mint an MCP-ready toolpack from web traffic.

set -euo pipefail

START_URL="${1:-https://app.example.com}"
ALLOWED_HOST="${2:-api.example.com}"

echo "Minting toolpack from ${START_URL} (allowed host: ${ALLOWED_HOST})"
caskmcp mint "${START_URL}" \
  --allowed-hosts "${ALLOWED_HOST}" \
  --scope agent_safe_readonly \
  --headless \
  --duration 30 \
  --print-mcp-config

echo ""
echo "Next:"
echo "  caskmcp mcp serve --toolpack .caskmcp/toolpacks/<toolpack-id>/toolpack.yaml"
echo "  caskmcp approve tool --all --toolset readonly --lockfile .caskmcp/toolpacks/<toolpack-id>/lockfile/caskmcp.lock.pending.yaml"
