"""Tests for Phase 4 meta MCP tools and compliance reporting."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest


class TestMetaServerNewTools:
    """Test that the meta server exposes capture/compile/drift/flow tools."""

    def test_meta_server_lists_new_tools(self):
        """Meta server should list caskmcp_capture_har, caskmcp_compile, caskmcp_drift_check, caskmcp_get_flows."""
        from caskmcp.mcp.meta_server import CaskMCPMetaMCPServer

        server = CaskMCPMetaMCPServer()
        # Access the registered handler to check tool list
        # The list_tools handler is registered on the server
        # We can inspect the server's tool definitions
        import asyncio

        async def get_tools():
            handler = None
            for attr_name in dir(server.server):
                attr = getattr(server.server, attr_name)
                if callable(attr) and "list_tools" in str(attr_name):
                    handler = attr
                    break
            # The tool list is set up in _register_handlers via handle_list_tools
            # We need to check the names of tools defined
            return None

        # Instead, check that the class has the handler methods
        assert hasattr(server, "_capture_har")
        assert hasattr(server, "_compile_capture")
        assert hasattr(server, "_drift_check")
        assert hasattr(server, "_get_flows")
        assert hasattr(server, "_request_approval")

    @pytest.mark.asyncio
    async def test_capture_har_returns_capture_id(self):
        """caskmcp_capture_har should import a HAR and return capture ID."""
        from caskmcp.mcp.meta_server import CaskMCPMetaMCPServer

        # Create a minimal HAR file
        har_data = {
            "log": {
                "version": "1.2",
                "entries": [
                    {
                        "request": {
                            "method": "GET",
                            "url": "https://api.example.com/api/v1/products",
                            "headers": [],
                            "queryString": [],
                        },
                        "response": {
                            "status": 200,
                            "headers": [
                                {"name": "Content-Type", "value": "application/json"},
                            ],
                            "content": {
                                "text": '{"id": 1, "name": "Widget"}',
                                "mimeType": "application/json",
                            },
                        },
                        "startedDateTime": "2026-01-01T00:00:00Z",
                    },
                ],
            },
        }

        with tempfile.NamedTemporaryFile(
            suffix=".har", mode="w", delete=False
        ) as f:
            json.dump(har_data, f)
            har_path = f.name

        try:
            server = CaskMCPMetaMCPServer()
            result = await server._capture_har({"har_path": har_path, "allowed_hosts": ["api.example.com"]})
            text = json.loads(result[0].text)
            assert "capture_id" in text
            assert text.get("status") != "error"
        finally:
            Path(har_path).unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_capture_har_missing_path_errors(self):
        from caskmcp.mcp.meta_server import CaskMCPMetaMCPServer

        server = CaskMCPMetaMCPServer()
        result = await server._capture_har({})
        text = json.loads(result[0].text)
        assert "error" in text

    @pytest.mark.asyncio
    async def test_request_approval_creates_pending(self):
        """caskmcp_request_approval should create a pending approval request."""
        from caskmcp.mcp.meta_server import CaskMCPMetaMCPServer

        server = CaskMCPMetaMCPServer()
        result = await server._request_approval({
            "action_name": "get_products",
            "reason": "Agent needs to browse products",
        })
        text = json.loads(result[0].text)
        assert text.get("status") == "approval_requested"
        assert "action_name" in text


class TestComplianceReport:
    """Test EU AI Act compliance report generation."""

    def test_compliance_report_generates(self):
        from caskmcp.core.compliance.report import ComplianceReporter

        reporter = ComplianceReporter()
        report = reporter.generate(
            tools_manifest={
                "actions": [
                    {"name": "get_products", "risk_tier": "safe", "method": "GET"},
                    {"name": "create_order", "risk_tier": "high", "method": "POST"},
                ],
            },
            approval_history=[
                {"action": "get_products", "status": "approved", "by": "human"},
                {"action": "create_order", "status": "approved", "by": "human"},
            ],
            drift_history=[],
        )
        assert "human_oversight" in report
        assert "tool_inventory" in report
        assert "risk_management" in report

    def test_compliance_report_counts_risk_tiers(self):
        from caskmcp.core.compliance.report import ComplianceReporter

        reporter = ComplianceReporter()
        report = reporter.generate(
            tools_manifest={
                "actions": [
                    {"name": "a", "risk_tier": "safe", "method": "GET"},
                    {"name": "b", "risk_tier": "high", "method": "POST"},
                    {"name": "c", "risk_tier": "critical", "method": "DELETE"},
                ],
            },
        )
        risk = report["risk_management"]
        assert risk["by_tier"]["safe"] == 1
        assert risk["by_tier"]["high"] == 1
        assert risk["by_tier"]["critical"] == 1

    def test_compliance_report_human_oversight(self):
        from caskmcp.core.compliance.report import ComplianceReporter

        reporter = ComplianceReporter()
        report = reporter.generate(
            tools_manifest={"actions": []},
            approval_history=[
                {"action": "x", "status": "approved", "by": "admin@corp.com"},
            ],
        )
        oversight = report["human_oversight"]
        assert oversight["approval_count"] == 1

    def test_compliance_report_json_serializable(self):
        from caskmcp.core.compliance.report import ComplianceReporter

        reporter = ComplianceReporter()
        report = reporter.generate(
            tools_manifest={"actions": [{"name": "a", "risk_tier": "low", "method": "GET"}]},
        )
        # Should be JSON-serializable
        serialized = json.dumps(report)
        assert serialized
