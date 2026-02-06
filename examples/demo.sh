#!/usr/bin/env bash
# CaskMCP Governance Demo
#
# This script demonstrates the complete workflow:
# 1. Import HAR traffic capture
# 2. Compile deterministic artifacts
# 3. Review and approve tools
# 4. Enforce + expose via MCP
#
# Prerequisites:
#   - pip install caskmcp
#   - A HAR file from browser DevTools (or use examples/sample.har)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║        CaskMCP: Governance + Enforcement Demo             ║${NC}"
echo -e "${BLUE}║   Compile, approve, enforce, and expose agent tools          ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if caskmcp is installed
if ! command -v caskmcp &> /dev/null; then
    echo -e "${RED}Error: caskmcp is not installed${NC}"
    echo "Run: pip install -e ."
    exit 1
fi

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_DIR="${SCRIPT_DIR}/.demo_output"

# Clean up any previous demo
rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR"
cd "$DEMO_DIR"

echo -e "${YELLOW}Step 1: Import HAR traffic capture${NC}"
echo "────────────────────────────────────────────────"
echo "In a real workflow, you'd export a HAR file from Chrome DevTools."
echo "We'll use the sample HAR file for this demo."
echo ""

caskmcp capture import "${SCRIPT_DIR}/sample.har" \
  --allowed-hosts api.example.com \
  --name "Demo Session" \
  --output .caskmcp/captures

CAPTURE_ID=$(ls .caskmcp/captures/ | head -1)
echo ""
echo -e "${GREEN}✓ Captured traffic from api.example.com${NC}"
echo "  Capture ID: ${CAPTURE_ID}"
echo ""

echo -e "${YELLOW}Step 2: Compile deterministic artifacts${NC}"
echo "────────────────────────────────────────────────"
echo "Compiling with 'first_party_only' scope - includes all first-party endpoints."
echo "(Use 'agent_safe_readonly' for production to restrict to safe GET endpoints)"
echo ""

caskmcp compile \
  --capture "${CAPTURE_ID}" \
  --scope first_party_only \
  --format all \
  --output .caskmcp/artifacts

ARTIFACT_DIR=$(ls .caskmcp/artifacts/ | head -1)
echo ""
echo -e "${GREEN}✓ Compiled artifacts:${NC}"
ls -la ".caskmcp/artifacts/${ARTIFACT_DIR}/"
echo ""

echo "Generated tools:"
cat ".caskmcp/artifacts/${ARTIFACT_DIR}/tools.json" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for action in data.get('actions', []):
    risk = action.get('risk_tier', 'low')
    color = {'low': '\033[32m', 'medium': '\033[33m', 'high': '\033[31m'}.get(risk, '')
    print(f\"  • {action['name']} [{color}{risk}\033[0m] {action['method']} {action['path']}\")
"
echo ""

echo -e "${YELLOW}Step 3: Review and approve tools${NC}"
echo "────────────────────────────────────────────────"
echo "Tools require explicit approval before use."
echo ""

# Sync lockfile
caskmcp approve sync \
  --tools ".caskmcp/artifacts/${ARTIFACT_DIR}/tools.json" \
  --policy ".caskmcp/artifacts/${ARTIFACT_DIR}/policy.yaml" \
  --toolsets ".caskmcp/artifacts/${ARTIFACT_DIR}/toolsets.yaml" \
  --lockfile caskmcp.lock.yaml || true

echo ""
echo "Lockfile created. Let's see what needs approval:"
caskmcp approve list --lockfile caskmcp.lock.yaml
echo ""

echo "Approving all tools for the demo..."
caskmcp approve tool --all --lockfile caskmcp.lock.yaml --by "demo@caskmcp.dev"
echo ""

echo "CI check (would run in your pipeline):"
caskmcp approve check --lockfile caskmcp.lock.yaml
echo ""

echo -e "${YELLOW}Step 4: Runtime enforcement + MCP${NC}"
echo "────────────────────────────────────────────────"
echo ""
echo -e "${BLUE}# Proxy mode with lockfile enables approval + integrity gating:${NC}"
echo "caskmcp enforce \\"
echo "  --tools .caskmcp/artifacts/${ARTIFACT_DIR}/tools.json \\"
echo "  --policy .caskmcp/artifacts/${ARTIFACT_DIR}/policy.yaml \\"
echo "  --lockfile caskmcp.lock.yaml \\"
echo "  --mode=proxy --base-url https://api.example.com --auth \"Bearer YOUR_API_TOKEN\""
echo ""
echo -e "${BLUE}# If a write is challenged, grant out-of-band:${NC}"
echo "caskmcp confirm grant <confirmation-token-id>"
echo ""
echo "To expose these tools to Claude or other AI agents:"
echo ""
echo -e "${BLUE}# Start the MCP server (dry-run mode - no actual API calls)${NC}"
echo "caskmcp mcp serve \\"
echo "  --tools .caskmcp/artifacts/${ARTIFACT_DIR}/tools.json \\"
echo "  --policy .caskmcp/artifacts/${ARTIFACT_DIR}/policy.yaml \\"
echo "  --dry-run"
echo ""
echo -e "${BLUE}# Or with real upstream API:${NC}"
echo "caskmcp mcp serve \\"
echo "  --tools .caskmcp/artifacts/${ARTIFACT_DIR}/tools.json \\"
echo "  --base-url https://api.example.com \\"
echo "  --auth \"Bearer YOUR_API_TOKEN\""
echo ""
echo -e "${BLUE}# Claude Desktop config (~/.claude/claude_desktop_config.json):${NC}"
cat << 'EOF'
{
  "mcpServers": {
    "my-api": {
      "command": "caskmcp",
      "args": [
        "mcp", "serve",
        "--tools", "/path/to/tools.json",
        "--policy", "/path/to/policy.yaml"
      ]
    }
  }
}
EOF
echo ""

echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    Demo Complete!                            ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "What happened:"
echo "  1. Imported API traffic from HAR file"
echo "  2. Compiled into versioned, safe tools"
echo "  3. Created approval lockfile for governance"
echo "  4. Ready to serve via MCP to AI agents"
echo ""
echo "Key files created:"
echo "  .caskmcp/captures/     - Raw traffic captures"
echo "  .caskmcp/artifacts/    - Compiled tools, policies, contracts"
echo "  caskmcp.lock.yaml      - Tool approvals and versions"
echo ""
echo "Next steps:"
echo "  • Add caskmcp.lock.yaml to git for version control"
echo "  • Run 'caskmcp approve check' in CI to gate deployments"
echo "  • Use drift detection when APIs change"
echo ""
echo -e "Demo output saved to: ${BLUE}${DEMO_DIR}${NC}"
