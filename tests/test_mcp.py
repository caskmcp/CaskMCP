"""Tests for the CaskMCP MCP server."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from caskmcp.core.approval import LockfileManager
from caskmcp.mcp.server import CaskMCPMCPServer


@pytest.fixture
def sample_tools_manifest() -> dict:
    """Create a sample tools manifest."""
    return {
        "version": "1.0.0",
        "schema_version": "1.0",
        "name": "Test Tools",
        "allowed_hosts": ["api.example.com"],
        "actions": [
            {
                "name": "get_users",
                "description": "Get list of users",
                "method": "GET",
                "path": "/api/users",
                "host": "api.example.com",
                "endpoint_id": "ep_123",
                "risk_tier": "low",
                "confirmation_required": "never",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "limit": {"type": "integer"},
                    },
                },
                "output_schema": {
                    "type": "object",
                    "properties": {
                        "users": {"type": "array"},
                    },
                },
            },
            {
                "name": "create_user",
                "description": "Create a new user",
                "method": "POST",
                "path": "/api/users",
                "host": "api.example.com",
                "endpoint_id": "ep_456",
                "risk_tier": "high",
                "confirmation_required": "always",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "email": {"type": "string"},
                    },
                },
            },
            {
                "name": "get_user",
                "description": "Get user by ID",
                "method": "GET",
                "path": "/api/users/{user_id}",
                "host": "api.example.com",
                "endpoint_id": "ep_789",
                "risk_tier": "low",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "user_id": {"type": "string"},
                    },
                },
            },
        ],
    }


@pytest.fixture
def sample_policy() -> dict:
    """Create a sample policy."""
    return {
        "name": "Test Policy",
        "default_action": "deny",
        "audit_all": True,
        "rules": [
            {
                "id": "allow_get",
                "name": "Allow GET requests",
                "type": "allow",
                "priority": 100,
                "match": {"methods": ["GET"]},
            },
            {
                "id": "confirm_post",
                "name": "Confirm POST requests",
                "type": "confirm",
                "priority": 90,
                "match": {"methods": ["POST"]},
                "settings": {"message": "This will create data. Proceed?"},
            },
        ],
    }


@pytest.fixture
def tools_file(sample_tools_manifest: dict, tmp_path: Path) -> Path:
    """Create a temporary tools.json file."""
    tools_path = tmp_path / "tools.json"
    with open(tools_path, "w") as f:
        json.dump(sample_tools_manifest, f)
    return tools_path


@pytest.fixture
def lockfile_file(
    sample_tools_manifest: dict,
    toolsets_file: Path,
    tmp_path: Path,
) -> Path:
    """Create lockfile with partial scoped approvals."""
    import yaml

    lockfile_path = tmp_path / "caskmcp.lock.yaml"
    manager = LockfileManager(lockfile_path)
    manager.load()
    with open(toolsets_file) as f:
        toolsets_payload = yaml.safe_load(f)

    manager.sync_from_manifest(sample_tools_manifest, toolsets=toolsets_payload)
    manager.approve("get_users", "security@example.com", toolset="readonly")
    manager.approve("get_user", "security@example.com", toolset="readonly")
    manager.save()
    return lockfile_path


@pytest.fixture
def toolsets_file(tmp_path: Path) -> Path:
    """Create a temporary toolsets.yaml file."""
    import yaml

    payload = {
        "version": "1.0.0",
        "schema_version": "1.0",
        "default_toolset": "readonly",
        "toolsets": {
            "readonly": {
                "description": "Readonly actions",
                "actions": ["get_users", "get_user"],
            },
            "operator": {
                "description": "Full action surface",
                "actions": ["get_users", "create_user", "get_user"],
            },
        },
    }
    path = tmp_path / "toolsets.yaml"
    with open(path, "w") as f:
        yaml.dump(payload, f)
    return path


@pytest.fixture
def policy_file(sample_policy: dict, tmp_path: Path) -> Path:
    """Create a temporary policy.yaml file."""
    import yaml

    policy_path = tmp_path / "policy.yaml"
    with open(policy_path, "w") as f:
        yaml.dump(sample_policy, f)
    return policy_path


class TestCaskMCPMCPServer:
    """Tests for CaskMCPMCPServer."""

    def test_init_loads_manifest(self, tools_file: Path) -> None:
        """Test server loads tools manifest."""
        server = CaskMCPMCPServer(tools_path=tools_file)

        assert len(server.actions) == 3
        assert "get_users" in server.actions
        assert "create_user" in server.actions
        assert "get_user" in server.actions

    def test_init_without_policy(self, tools_file: Path) -> None:
        """Test server initializes without policy."""
        server = CaskMCPMCPServer(tools_path=tools_file)

        assert server.enforcer is None

    def test_init_with_toolset_filters_actions(
        self,
        tools_file: Path,
        toolsets_file: Path,
    ) -> None:
        """Server should expose only actions in selected toolset."""
        server = CaskMCPMCPServer(
            tools_path=tools_file,
            toolsets_path=toolsets_file,
            toolset_name="readonly",
        )

        assert len(server.actions) == 2
        assert "get_users" in server.actions
        assert "get_user" in server.actions
        assert "create_user" not in server.actions

    def test_init_with_missing_toolset_raises(
        self,
        tools_file: Path,
        toolsets_file: Path,
    ) -> None:
        """Unknown toolset should fail server initialization."""
        with pytest.raises(ValueError, match="Unknown toolset"):
            CaskMCPMCPServer(
                tools_path=tools_file,
                toolsets_path=toolsets_file,
                toolset_name="does_not_exist",
            )

    def test_init_with_lockfile_enforces_approvals(
        self,
        tools_file: Path,
        toolsets_file: Path,
        lockfile_file: Path,
    ) -> None:
        """When lockfile is provided, only approved tools are exposed."""
        server = CaskMCPMCPServer(
            tools_path=tools_file,
            toolsets_path=toolsets_file,
            toolset_name="readonly",
            lockfile_path=lockfile_file,
        )

        assert set(server.actions) == {"get_users", "get_user"}

    def test_init_without_lockfile_does_not_require_approvals(
        self,
        tools_file: Path,
        toolsets_file: Path,
    ) -> None:
        """Without lockfile, all tools in toolset are exposed (no approval gate)."""
        server = CaskMCPMCPServer(
            tools_path=tools_file,
            toolsets_path=toolsets_file,
            toolset_name="operator",
        )

        assert set(server.actions) == {"get_users", "get_user", "create_user"}

    def test_init_with_policy(self, tools_file: Path, policy_file: Path) -> None:
        """Test server initializes with policy."""
        server = CaskMCPMCPServer(
            tools_path=tools_file,
            policy_path=policy_file,
        )

        assert server.enforcer is not None
        assert server.enforcer.policy.name == "Test Policy"

    def test_build_description_low_risk(self, tools_file: Path) -> None:
        """Test description building for low-risk tool."""
        server = CaskMCPMCPServer(tools_path=tools_file)
        action = server.actions["get_users"]

        desc = server._build_description(action)

        assert desc == "Get list of users"
        assert "[Risk:" not in desc

    def test_build_description_high_risk(self, tools_file: Path) -> None:
        """Test description building for high-risk tool."""
        server = CaskMCPMCPServer(tools_path=tools_file)
        action = server.actions["create_user"]

        desc = server._build_description(action)

        assert "Create a new user" in desc
        assert "[Risk: high]" in desc
        assert "[Requires confirmation]" in desc


class TestMCPServerHandlers:
    """Tests for MCP protocol handlers."""

    @pytest.mark.asyncio
    async def test_list_tools(self, tools_file: Path) -> None:
        """Test listing available tools."""
        server = CaskMCPMCPServer(tools_path=tools_file)

        # Get the list_tools handler from registered handlers
        # We need to access the internal handler
        tools = []
        for action in server.actions.values():
            from mcp import types

            tool = types.Tool(
                name=action["name"],
                description=server._build_description(action),
                inputSchema=action.get("input_schema", {"type": "object", "properties": {}}),
            )
            tools.append(tool)

        assert len(tools) == 3
        tool_names = [t.name for t in tools]
        assert "get_users" in tool_names
        assert "create_user" in tool_names
        assert "get_user" in tool_names


class TestMCPServerDryRun:
    """Tests for dry run mode."""

    def test_dry_run_flag(self, tools_file: Path) -> None:
        """Test dry run flag is set."""
        server = CaskMCPMCPServer(
            tools_path=tools_file,
            dry_run=True,
        )

        assert server.dry_run is True

    def test_base_url_override(self, tools_file: Path) -> None:
        """Test base URL override."""
        server = CaskMCPMCPServer(
            tools_path=tools_file,
            base_url="https://custom.api.com",
        )

        assert server.base_url == "https://custom.api.com"

    def test_auth_header(self, tools_file: Path) -> None:
        """Test auth header configuration."""
        server = CaskMCPMCPServer(
            tools_path=tools_file,
            auth_header="Bearer test_token",
        )

        assert server.auth_header == "Bearer test_token"
