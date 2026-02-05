# Actionforge Examples

This directory contains example files to help you get started with Actionforge.

## 60-Second Interactive Demo

Run the complete workflow with a single command:

```bash
./examples/demo.sh
```

This script demonstrates:
1. Importing HAR traffic capture
2. Compiling into safe, agent-ready tools
3. Reviewing and approving tools
4. Configuring MCP server for AI agents

For unattended CI coverage of the full governance wedge (approval + confirmation + drift gate), run:

```bash
bash scripts/magic_moment_ci.sh
```

## Manual Workflow

Run through the complete workflow step-by-step:

```bash
# 1. Import the sample HAR file
actionforge capture import examples/sample.har \
  --allowed-hosts api.example.com \
  --name "Demo Session"

# 2. Compile into artifacts
actionforge compile \
  --capture <capture-id-from-step-1> \
  --scope first_party_only \
  --format all

# 3. View the generated artifacts
ls .actionforge/artifacts/
cat .actionforge/artifacts/*/contract.yaml
cat .actionforge/artifacts/*/tools.json
```

## Files

### `sample.har`

A sample HAR file containing typical API traffic:

- `GET /api/users` - List users
- `GET /api/users/{id}` - Get user by ID
- `POST /api/users` - Create user
- `PUT /api/users/{id}` - Update user
- `DELETE /api/users/{id}` - Delete user
- `GET /api/products` - List products
- `GET /api/products/{id}` - Get product by ID
- `POST /api/orders` - Create order

### `custom-scope.yaml`

Example custom scope for filtering to specific endpoints:

```yaml
name: orders_only
description: "Only order-related endpoints"
default_action: exclude
rules:
  - id: include_orders
    action: include
    filters:
      - field: path
        operator: contains
        value: "/orders"
```

### `strict-policy.yaml`

Example strict policy for production use:

```yaml
name: "Strict Production Policy"
default_action: deny
audit_all: true

rules:
  - id: allow_reads
    type: allow
    priority: 100
    match:
      methods: [GET]

  - id: confirm_all_writes
    type: confirm
    priority: 90
    match:
      methods: [POST, PUT, PATCH, DELETE]
    settings:
      message: "This action will modify data. Confirm?"

  - id: rate_limit_writes
    type: budget
    priority: 80
    match:
      methods: [POST, PUT, PATCH, DELETE]
    settings:
      per_minute: 5
      per_hour: 50
```

## Expected Output

After running the demo, you should see:

1. **Capture saved** with an ID like `cap_20240204_abc12345`
2. **Artifacts generated** including:
   - `contract.yaml` - OpenAPI 3.1 spec with 8 endpoints
   - `tools.json` - 8 agent-callable actions
   - `policy.yaml` - Default enforcement policy
   - `baseline.json` - Drift detection baseline

## Approval Workflow

Review and approve tools before use:

```bash
# Sync lockfile with generated tools
actionforge approve sync --tools .actionforge/artifacts/*/tools.json

# List pending approvals
actionforge approve list --status pending

# Approve specific tools
actionforge approve tool get_users get_products

# Or approve all pending tools
actionforge approve tool --all --by "security@team.com"

# Reject dangerous tools
actionforge approve reject delete_all_users --reason "Too dangerous"

# CI check (for pipelines)
actionforge approve check
```

## Testing Drift Detection

1. Modify the HAR file (e.g., remove an endpoint)
2. Import as a new capture
3. Run drift detection:

```bash
actionforge drift --from <old-capture> --to <new-capture>
```

You should see drift detected for the removed endpoint.

## Running the MCP Server

Expose your compiled tools to AI agents like Claude:

```bash
# Basic usage (dry run - no actual API calls)
actionforge mcp serve \
  --tools .actionforge/artifacts/*/tools.json \
  --dry-run

# With policy enforcement
actionforge mcp serve \
  --tools .actionforge/artifacts/*/tools.json \
  --policy .actionforge/artifacts/*/policy.yaml

# With upstream API configuration
actionforge mcp serve \
  --tools .actionforge/artifacts/*/tools.json \
  --base-url https://api.example.com \
  --auth "Bearer your-api-token"
```

### Claude Desktop Configuration

Add to `~/.claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "my-api": {
      "command": "actionforge",
      "args": [
        "mcp", "serve",
        "--tools", "/path/to/tools.json",
        "--policy", "/path/to/policy.yaml"
      ]
    }
  }
}
```

Then Claude can discover and use your API tools safely, with:
- Policy enforcement (allow/deny/confirm)
- Rate limiting
- Audit logging
- Confirmation for risky operations
