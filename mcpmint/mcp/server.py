"""MCP server implementation for MCPMint."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import socket
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urljoin, urlparse

import httpx
import yaml

from mcpmint.core.approval import (
    ApprovalStatus,
    LockfileManager,
    compute_artifacts_digest_from_paths,
    compute_lockfile_digest,
)
from mcpmint.core.audit import AuditLogger, FileAuditBackend, MemoryAuditBackend
from mcpmint.core.enforce import ConfirmationStore, DecisionEngine, PolicyEngine
from mcpmint.mcp._compat import (
    InitializationOptions,
    NotificationOptions,
    Server,
    mcp_stdio,
)
from mcpmint.mcp._compat import (
    mcp_types as types,
)
from mcpmint.models.decision import (
    DecisionContext,
    DecisionRequest,
    DecisionType,
    NetworkSafetyConfig,
    ReasonCode,
)
from mcpmint.utils.schema_version import resolve_schema_version

logger = logging.getLogger(__name__)


class RuntimeBlockError(Exception):
    """Raised when runtime network controls deny execution."""

    def __init__(self, reason_code: ReasonCode, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.message = message


class MCPMintMCPServer:
    """MCP server that exposes MCPMint tools with runtime enforcement."""

    def __init__(
        self,
        tools_path: str | Path,
        toolsets_path: str | Path | None = None,
        toolset_name: str | None = None,
        policy_path: str | Path | None = None,
        lockfile_path: str | Path | None = None,
        base_url: str | None = None,
        auth_header: str | None = None,
        audit_log: str | Path | None = None,
        dry_run: bool = False,
        confirmation_store_path: str | Path = ".mcpmint/confirmations.db",
        allow_private_cidrs: list[str] | None = None,
        allow_redirects: bool = False,
    ) -> None:
        self.tools_path = Path(tools_path)
        self.toolsets_path = Path(toolsets_path) if toolsets_path else None
        self.toolset_name = toolset_name
        self.policy_path = Path(policy_path) if policy_path else None
        self.lockfile_path = Path(lockfile_path) if lockfile_path else None
        self.base_url = base_url
        self.auth_header = auth_header
        self.dry_run = dry_run
        self.allow_private_networks = [
            ipaddress.ip_network(cidr)
            for cidr in (allow_private_cidrs or [])
        ]
        self.allow_redirects = allow_redirects

        with open(self.tools_path) as f:
            self.manifest: dict[str, Any] = json.load(f)
        resolve_schema_version(
            self.manifest,
            artifact="tools manifest",
            allow_legacy=True,
        )

        self.toolsets_payload: dict[str, Any] | None = None
        selected_action_names: set[str] | None = None
        if self.toolsets_path is not None:
            with open(self.toolsets_path) as f:
                self.toolsets_payload = yaml.safe_load(f) or {}
            resolve_schema_version(
                self.toolsets_payload,
                artifact="toolsets artifact",
                allow_legacy=False,
            )

            if self.toolset_name:
                toolsets = self.toolsets_payload.get("toolsets", {})
                if self.toolset_name not in toolsets:
                    available = ", ".join(sorted(toolsets))
                    raise ValueError(
                        f"Unknown toolset '{self.toolset_name}'. Available: {available}"
                    )
                selected_action_names = set(toolsets[self.toolset_name].get("actions", []))

        self.lockfile_manager: LockfileManager | None = None
        self.lockfile_digest_current: str | None = None
        if self.lockfile_path is not None:
            manager = LockfileManager(self.lockfile_path)
            if not manager.exists():
                raise ValueError(f"Lockfile not found: {manager.lockfile_path}")
            lockfile = manager.load()
            self.lockfile_manager = manager
            self.lockfile_digest_current = compute_lockfile_digest(lockfile.model_dump(mode="json"))

        self.actions: dict[str, dict[str, Any]] = {}
        self.actions_by_tool_id: dict[str, dict[str, Any]] = {}
        for action in self.manifest.get("actions", []):
            if selected_action_names is not None and action.get("name") not in selected_action_names:
                continue
            if not self._is_action_exposed(action):
                continue
            self.actions[action["name"]] = action
            tool_id = str(action.get("tool_id") or action.get("signature_id") or action.get("name"))
            self.actions_by_tool_id[tool_id] = action
            self.actions_by_tool_id[action["name"]] = action

        if selected_action_names is not None:
            missing = sorted(selected_action_names - set(self.actions))
            if missing:
                raise ValueError(
                    f"Toolset '{self.toolset_name}' references missing tools: {', '.join(missing)}"
                )

        backend = FileAuditBackend(audit_log) if audit_log else MemoryAuditBackend()
        self.audit_logger = AuditLogger(backend)

        self.policy_engine: PolicyEngine | None = None
        if self.policy_path and self.policy_path.exists():
            self.policy_engine = PolicyEngine.from_file(str(self.policy_path))
        # Backward-compatible alias used by existing tests/callers.
        self.enforcer = self.policy_engine

        toolsets_for_digest: str | None = str(self.toolsets_path) if self.toolsets_path else None
        policy_for_digest: str | None = str(self.policy_path) if self.policy_path else None
        self.artifacts_digest_current = compute_artifacts_digest_from_paths(
            tools_path=self.tools_path,
            toolsets_path=toolsets_for_digest,
            policy_path=policy_for_digest,
        )

        self.confirmation_store = ConfirmationStore(confirmation_store_path)
        self.decision_engine = DecisionEngine(self.confirmation_store)
        self.decision_context = DecisionContext(
            manifest_view=self.actions_by_tool_id,
            policy=self.policy_engine.policy if self.policy_engine else None,
            policy_engine=self.policy_engine,
            lockfile=self.lockfile_manager,
            toolsets=self.toolsets_payload,
            network_safety=NetworkSafetyConfig(
                allow_private_cidrs=allow_private_cidrs or [],
                allow_redirects=allow_redirects,
                max_redirects=3,
            ),
            artifacts_digest_current=self.artifacts_digest_current,
            lockfile_digest_current=self.lockfile_digest_current,
        )

        self.server = Server("mcpmint")
        self._register_handlers()
        self._http_client: httpx.AsyncClient | None = None

        logger.info(
            "Initialized MCPMint MCP server with %s tools",
            len(self.actions),
        )

    def _is_action_exposed(self, action: dict[str, Any]) -> bool:
        if self.lockfile_manager is None:
            return True

        action_name = str(action.get("name", ""))
        action_signature = str(action.get("signature_id", ""))
        action_tool_id = str(action.get("tool_id") or action_signature or action_name)

        tool = self.lockfile_manager.get_tool(action_signature) if action_signature else None
        if tool is None:
            tool = self.lockfile_manager.get_tool(action_tool_id)
        if tool is None:
            tool = self.lockfile_manager.get_tool(action_name)
        if tool is None:
            return False

        if self.toolset_name:
            if tool.status == ApprovalStatus.REJECTED:
                return False
            if tool.toolsets and self.toolset_name not in tool.toolsets:
                return False
            if tool.approved_toolsets:
                return self.toolset_name in tool.approved_toolsets
            return tool.status == ApprovalStatus.APPROVED

        return tool.status == ApprovalStatus.APPROVED

    def _register_handlers(self) -> None:
        @self.server.list_tools()  # type: ignore
        async def handle_list_tools() -> list[types.Tool]:
            tools = []
            for action in self.actions.values():
                tool = types.Tool(
                    name=action["name"],
                    description=self._build_description(action),
                    inputSchema=action.get("input_schema", {"type": "object", "properties": {}}),
                )
                if "output_schema" in action:
                    tool.outputSchema = action["output_schema"]
                tools.append(tool)
            return tools

        @self.server.call_tool()  # type: ignore
        async def handle_call_tool(
            name: str,
            arguments: dict[str, Any] | None,
        ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
            arguments = arguments or {}
            action = self.actions.get(name)
            if not action:
                return [types.TextContent(
                    type="text",
                    text=json.dumps({"error": f"Unknown tool: {name}"}),
                )]

            method, path, host = self._resolve_action_endpoint(action)
            tool_id = str(action.get("tool_id") or action.get("signature_id") or name)
            confirmation_token_id = (
                arguments.get("confirmation_token_id")
                or arguments.get("_confirmation_token_id")
            )
            call_args = {
                k: v
                for k, v in arguments.items()
                if k not in {"confirmation_token_id", "_confirmation_token_id"}
            }

            request = DecisionRequest(
                tool_id=tool_id,
                action_name=name,
                method=method,
                path=path,
                host=host,
                params=call_args,
                toolset_name=self.toolset_name,
                confirmation_token_id=str(confirmation_token_id) if confirmation_token_id else None,
                source="mcp",
                mode="execute",
            )
            decision = self.decision_engine.evaluate(request, self.decision_context)

            if decision.decision == DecisionType.CONFIRM:
                if decision.confirmation_token_id:
                    print(
                        f"[mcpmint] Confirmation required for {name}. "
                        f"Run: mcpmint confirm grant {decision.confirmation_token_id}",
                        flush=True,
                    )
                return [types.TextContent(
                    type="text",
                    text=json.dumps({
                        "status": "confirmation_required",
                        "decision": decision.decision.value,
                        "reason_code": decision.reason_code.value,
                        "reason": decision.reason_message,
                        "confirmation_token_id": decision.confirmation_token_id,
                        "action": name,
                    }),
                )]

            if decision.decision == DecisionType.DENY:
                return [types.TextContent(
                    type="text",
                    text=json.dumps({
                        "status": "blocked",
                        "decision": decision.decision.value,
                        "reason_code": decision.reason_code.value,
                        "reason": decision.reason_message,
                        "action": name,
                        "audit_fields": decision.audit_fields,
                    }),
                )]

            if self.dry_run:
                return [types.TextContent(
                    type="text",
                    text=json.dumps({
                        "status": "dry_run",
                        "action": name,
                        "method": method,
                        "path": path,
                        "arguments": call_args,
                        "message": "Request would be sent (dry run mode)",
                        "decision": decision.decision.value,
                        "reason_code": decision.reason_code.value,
                    }),
                )]

            try:
                response = await self._execute_request(action, call_args)
                return [types.TextContent(type="text", text=json.dumps(response))]
            except RuntimeBlockError as blocked:
                return [types.TextContent(
                    type="text",
                    text=json.dumps({
                        "status": "blocked",
                        "action": name,
                        "decision": DecisionType.DENY.value,
                        "reason_code": blocked.reason_code.value,
                        "reason": blocked.message,
                    }),
                )]
            except Exception as e:
                logger.exception("Error executing %s", name)
                return [types.TextContent(
                    type="text",
                    text=json.dumps({
                        "status": "error",
                        "action": name,
                        "reason_code": ReasonCode.ERROR_INTERNAL.value,
                        "error": str(e),
                    }),
                )]

    def _build_description(self, action: dict[str, Any]) -> str:
        desc: str = action.get("description", f"{action.get('method', 'GET')} {action.get('path', '/')}")
        risk = action.get("risk_tier", "low")
        if risk in ("high", "critical"):
            desc += f" [Risk: {risk}]"
        if action.get("confirmation_required") == "always":
            desc += " [Requires confirmation]"
        return desc

    def _resolve_action_endpoint(self, action: dict[str, Any]) -> tuple[str, str, str]:
        endpoint = action.get("endpoint")
        endpoint_data = endpoint if isinstance(endpoint, dict) else {}

        method = endpoint_data.get("method") or action.get("method") or "GET"
        path = endpoint_data.get("path") or action.get("path") or "/"
        host = endpoint_data.get("host") or action.get("host") or ""
        return str(method), str(path), str(host)

    async def _get_http_client(self) -> httpx.AsyncClient:
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(timeout=30.0)
        return self._http_client

    def _resolved_ips(self, host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        try:
            infos = socket.getaddrinfo(host, None)
        except OSError as exc:
            raise RuntimeBlockError(
                ReasonCode.DENIED_HOST_RESOLUTION_FAILED,
                f"Failed to resolve host '{host}': {exc}",
            ) from exc

        ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        for info in infos:
            addr = info[4][0]
            try:
                ips.append(ipaddress.ip_address(addr))
            except ValueError:
                continue

        if not ips:
            raise RuntimeBlockError(
                ReasonCode.DENIED_HOST_RESOLUTION_FAILED,
                f"No valid IPs resolved for host '{host}'",
            )
        return ips

    def _is_ip_allowed(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            return False
        if ip.is_private:
            return any(ip in network for network in self.allow_private_networks)
        return True

    def _validate_network_target(self, host: str) -> None:
        for ip in self._resolved_ips(host):
            if not self._is_ip_allowed(ip):
                raise RuntimeBlockError(
                    ReasonCode.DENIED_HOST_RESOLUTION_FAILED,
                    f"Resolved host '{host}' to blocked address {ip}",
                )

    def _validate_host_allowlist(self, target_host: str, action_host: str) -> None:
        allowed_hosts = {str(h).lower() for h in self.manifest.get("allowed_hosts", [])}
        if target_host.lower() == action_host.lower():
            return
        if target_host.lower() in allowed_hosts:
            return
        raise RuntimeBlockError(
            ReasonCode.DENIED_REDIRECT_NOT_ALLOWLISTED,
            f"Host '{target_host}' is not allowlisted for action host '{action_host}'",
        )

    async def _execute_request(
        self,
        action: dict[str, Any],
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        method, path, action_host = self._resolve_action_endpoint(action)
        url = urljoin(self.base_url, path) if self.base_url else f"https://{action_host}{path}"

        for param_name, param_value in arguments.items():
            placeholder = f"{{{param_name}}}"
            if placeholder in path:
                url = url.replace(placeholder, str(param_value))

        headers: dict[str, str] = {"User-Agent": "MCPMint-MCP/1.0"}
        if self.auth_header:
            headers["Authorization"] = self.auth_header

        kwargs: dict[str, Any] = {"headers": headers, "follow_redirects": False}
        if method.upper() in ("POST", "PUT", "PATCH"):
            body_params = {
                k: v for k, v in arguments.items()
                if f"{{{k}}}" not in path
            }
            if body_params:
                headers["Content-Type"] = "application/json"
                kwargs["json"] = body_params
        elif method.upper() in ("GET", "HEAD", "OPTIONS"):
            query_params = {
                k: v for k, v in arguments.items()
                if f"{{{k}}}" not in path
            }
            if query_params:
                url = f"{url}?{urlencode(query_params)}"

        client = await self._get_http_client()
        current_url = url

        for _ in range(4):
            parsed = urlparse(current_url)
            target_host = parsed.hostname or action_host
            self._validate_host_allowlist(target_host, action_host)
            self._validate_network_target(target_host)

            response = await client.request(method.upper(), current_url, **kwargs)
            if response.status_code in {301, 302, 303, 307, 308}:
                location = response.headers.get("location")
                if not location:
                    break
                if not self.allow_redirects:
                    raise RuntimeBlockError(
                        ReasonCode.DENIED_REDIRECT_NOT_ALLOWLISTED,
                        f"Redirect blocked for {current_url} -> {location}",
                    )
                next_url = urljoin(current_url, location)
                next_host = urlparse(next_url).hostname
                if not next_host:
                    raise RuntimeBlockError(
                        ReasonCode.DENIED_REDIRECT_NOT_ALLOWLISTED,
                        f"Redirect target '{location}' has no host",
                    )
                self._validate_host_allowlist(next_host, action_host)
                self._validate_network_target(next_host)
                current_url = next_url
                continue

            content_type = response.headers.get("content-type", "")
            if content_type.startswith("application/octet-stream"):
                raise RuntimeBlockError(
                    ReasonCode.DENIED_CONTENT_TYPE_NOT_ALLOWED,
                    f"Blocked response content type: {content_type}",
                )

            result: dict[str, Any] = {
                "status": "success",
                "status_code": response.status_code,
                "action": action["name"],
            }
            if "application/json" in content_type:
                try:
                    result["data"] = response.json()
                except json.JSONDecodeError:
                    result["data"] = response.text
            else:
                result["data"] = response.text

            self.audit_logger.log_enforce_decision(
                action_id=action["name"],
                endpoint_id=action.get("endpoint_id"),
                method=method,
                path=path,
                host=target_host,
                decision="allowed",
                confirmation_required=False,
            )
            return result

        raise RuntimeBlockError(
            ReasonCode.DENIED_REDIRECT_NOT_ALLOWLISTED,
            "Maximum redirect hops exceeded",
        )

    async def run_stdio(self) -> None:
        async with mcp_stdio.stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="mcpmint",
                    server_version="1.0.0",
                    capabilities=self.server.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )

    async def close(self) -> None:
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None


def run_mcp_server(
    tools_path: str,
    toolsets_path: str | None = None,
    toolset_name: str | None = None,
    policy_path: str | None = None,
    lockfile_path: str | None = None,
    base_url: str | None = None,
    auth_header: str | None = None,
    audit_log: str | None = None,
    dry_run: bool = False,
    confirmation_store_path: str = ".mcpmint/confirmations.db",
    allow_private_cidrs: list[str] | None = None,
    allow_redirects: bool = False,
) -> None:
    """Run the MCPMint MCP server."""
    server = MCPMintMCPServer(
        tools_path=tools_path,
        toolsets_path=toolsets_path,
        toolset_name=toolset_name,
        policy_path=policy_path,
        lockfile_path=lockfile_path,
        base_url=base_url,
        auth_header=auth_header,
        audit_log=audit_log,
        dry_run=dry_run,
        confirmation_store_path=confirmation_store_path,
        allow_private_cidrs=allow_private_cidrs,
        allow_redirects=allow_redirects,
    )

    async def main() -> None:
        try:
            await server.run_stdio()
        finally:
            await server.close()

    asyncio.run(main())
