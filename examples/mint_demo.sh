#!/usr/bin/env bash
# MCPMint Mint Demo
#
# One command to mint an MCP-ready toolpack from web traffic.

set -euo pipefail

START_URL="${1:-https://app.example.com}"
ALLOWED_HOST="${2:-api.example.com}"

echo "Minting toolpack from ${START_URL} (allowed host: ${ALLOWED_HOST})"
mcpmint mint "${START_URL}" \
  --allowed-hosts "${ALLOWED_HOST}" \
  --scope agent_safe_readonly \
  --headless \
  --duration 30 \
  --print-mcp-config

echo ""
echo "Next:"
echo "  mcpmint mcp serve --toolpack .mcpmint/toolpacks/<toolpack-id>/toolpack.yaml"
echo "  mcpmint approve tool --all --toolset readonly --lockfile .mcpmint/toolpacks/<toolpack-id>/lockfile/mcpmint.lock.pending.yaml"
