"""Enforce command implementation."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import click
import httpx
import yaml

from mcpmint.core.approval import (
    LockfileManager,
    compute_artifacts_digest_from_paths,
    compute_lockfile_digest,
)
from mcpmint.core.audit import AuditLogger, FileAuditBackend, MemoryAuditBackend
from mcpmint.core.enforce import ConfirmationStore, DecisionEngine, PolicyEngine
from mcpmint.models.decision import (
    DecisionContext,
    DecisionRequest,
    DecisionResult,
    DecisionType,
    NetworkSafetyConfig,
    ReasonCode,
)
from mcpmint.utils.schema_version import resolve_schema_version


class RuntimeBlockError(Exception):
    """Execution blocked by runtime safety checks."""

    def __init__(self, reason_code: ReasonCode, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.message = message


class EnforcementGateway:
    """HTTP gateway for policy enforcement."""

    def __init__(
        self,
        tools_path: str,
        policy_path: str,
        toolsets_path: str | None = None,
        toolset_name: str | None = None,
        audit_log: str | None = None,
        dry_run: bool = False,
        verbose: bool = False,
        mode: str = "evaluate",
        base_url: str | None = None,
        auth_header: str | None = None,
        lockfile_path: str | None = None,
        confirmation_store_path: str | None = None,
        allow_private_cidrs: list[str] | None = None,
        allow_redirects: bool = False,
        unsafe_no_lockfile: bool = False,
    ) -> None:
        """Initialize the gateway."""
        self.dry_run = dry_run
        self.verbose = verbose
        self.mode = mode
        self.base_url = base_url
        self.auth_header = auth_header
        self.lockfile_path = lockfile_path
        self.toolsets_path = toolsets_path
        self.toolset_name = toolset_name
        self.unsafe_no_lockfile = unsafe_no_lockfile

        self.allow_private_networks = [
            ipaddress.ip_network(cidr)
            for cidr in (allow_private_cidrs or [])
        ]
        self.allow_redirects = allow_redirects

        # HTTP client for proxy mode (lazy initialized)
        self._http_client: httpx.AsyncClient | None = None

        with open(tools_path) as f:
            self.tools_manifest = json.load(f)
        resolve_schema_version(
            self.tools_manifest,
            artifact="tools manifest",
            allow_legacy=True,
        )

        self.toolsets_payload = self._load_toolsets_payload(tools_path, toolsets_path)
        selected_action_names = self._resolve_toolset_actions(toolset_name)

        # Build action lookup keyed by both tool_id and name for compatibility.
        self.actions: dict[str, dict[str, Any]] = {}
        self.actions_by_name: dict[str, dict[str, Any]] = {}
        for action in self.tools_manifest.get("actions", []):
            if selected_action_names is not None and action.get("name") not in selected_action_names:
                continue
            tool_id = str(action.get("tool_id") or action.get("signature_id") or action.get("name"))
            self.actions[tool_id] = action
            if action.get("name"):
                self.actions[str(action["name"])] = action
                self.actions_by_name[str(action["name"])] = action

        backend = FileAuditBackend(audit_log) if audit_log else MemoryAuditBackend()
        self.audit_logger = AuditLogger(backend)

        self.policy_engine = PolicyEngine.from_file(policy_path)

        self.lockfile_manager: LockfileManager | None = None
        self.lockfile_digest_current: str | None = None
        if self.mode == "proxy" and not lockfile_path and not self.unsafe_no_lockfile:
            raise ValueError(
                "Proxy mode requires lockfile unless unsafe_no_lockfile is enabled"
            )
        if lockfile_path:
            manager = LockfileManager(lockfile_path)
            if not manager.exists():
                raise ValueError(f"Lockfile not found: {manager.lockfile_path}")
            lockfile = manager.load()
            self.lockfile_manager = manager
            self.lockfile_digest_current = compute_lockfile_digest(lockfile.model_dump(mode="json"))

        toolsets_for_digest: str | None = None
        if self.toolsets_payload is not None:
            toolsets_for_digest = str(Path(toolsets_path) if toolsets_path else Path(tools_path).parent / "toolsets.yaml")

        self.artifacts_digest_current = compute_artifacts_digest_from_paths(
            tools_path=tools_path,
            toolsets_path=toolsets_for_digest,
            policy_path=policy_path,
        )

        resolved_confirmation_store = (
            confirmation_store_path
            or str(Path(policy_path).parent / ".mcpmint" / "confirmations.db")
        )
        self.confirmation_store = ConfirmationStore(resolved_confirmation_store)
        self.decision_engine = DecisionEngine(self.confirmation_store)

        self.decision_context = DecisionContext(
            manifest_view=self.actions,
            policy=self.policy_engine.policy,
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

        if verbose:
            click.echo(f"Loaded {len(self.actions_by_name)} actions from tools manifest")
            if self.toolset_name:
                click.echo(f"  Toolset: {self.toolset_name}")
            click.echo(f"Loaded policy: {self.policy_engine.policy.name}")
            click.echo(f"  Rules: {len(self.policy_engine.policy.rules)}")
            click.echo(f"  Mode: {mode}")
            click.echo(f"  Artifacts digest: {self.artifacts_digest_current[:16]}...")

    def _load_toolsets_payload(
        self,
        tools_path: str,
        toolsets_path: str | None,
    ) -> dict[str, Any] | None:
        resolved: Path | None
        if toolsets_path:
            resolved = Path(toolsets_path)
        else:
            candidate = Path(tools_path).parent / "toolsets.yaml"
            resolved = candidate if candidate.exists() else None

        if resolved is None:
            return None

        with open(resolved) as f:
            payload = yaml.safe_load(f) or {}
        resolve_schema_version(payload, artifact="toolsets artifact", allow_legacy=False)
        return payload

    def _resolve_toolset_actions(self, toolset_name: str | None) -> set[str] | None:
        if not toolset_name:
            return None

        if self.toolsets_payload is None:
            raise ValueError(
                "Toolset selection requires toolsets artifact; pass --toolsets or compile toolsets.yaml"
            )

        toolsets = self.toolsets_payload.get("toolsets", {})
        if toolset_name not in toolsets:
            available = ", ".join(sorted(toolsets))
            raise ValueError(f"Unknown toolset '{toolset_name}'. Available: {available}")

        selected = set(toolsets[toolset_name].get("actions", []))
        manifest_actions = {
            str(a.get("name"))
            for a in self.tools_manifest.get("actions", [])
            if a.get("name")
        }
        missing = sorted(selected - manifest_actions)
        if missing:
            raise ValueError(
                f"Toolset '{toolset_name}' references missing tools: {', '.join(missing)}"
            )

        return selected

    def _resolve_action_endpoint(self, action: dict[str, Any]) -> tuple[str, str, str]:
        endpoint = action.get("endpoint")
        endpoint_data = endpoint if isinstance(endpoint, dict) else {}

        method = endpoint_data.get("method") or action.get("method") or "GET"
        path = endpoint_data.get("path") or action.get("path") or "/"
        host = endpoint_data.get("host") or action.get("host") or "unknown"

        return str(method), str(path), str(host)

    def _decision_to_payload(self, result: DecisionResult) -> dict[str, Any]:
        budget_remaining = result.budget_effects.get("budget_remaining")
        budget_exceeded = bool(result.budget_effects.get("budget_exceeded", False))
        rule_id = result.audit_fields.get("rule_id")
        return {
            "decision": result.decision.value,
            "reason_code": result.reason_code.value,
            "reason": result.reason_message,
            "allowed": result.decision == DecisionType.ALLOW,
            "requires_confirmation": result.decision == DecisionType.CONFIRM,
            "confirmation_token_id": result.confirmation_token_id,
            "confirmation_token": result.confirmation_token_id,
            "confirmation_message": (
                "State-changing request requires out-of-band approval"
                if result.decision == DecisionType.CONFIRM
                else None
            ),
            "budget_exceeded": budget_exceeded,
            "budget_remaining": budget_remaining,
            "rule_id": rule_id,
            "redaction_summary": result.redaction_summary,
            "budget_effects": result.budget_effects,
            "audit_fields": result.audit_fields,
            "dry_run": self.dry_run,
        }

    def _build_decision_request(
        self,
        action_name: str,
        params: dict[str, Any] | None,
        confirmation_token: str | None,
        mode: str,
    ) -> DecisionRequest | None:
        action = self.actions_by_name.get(action_name)
        if not action:
            return None

        method, path, host = self._resolve_action_endpoint(action)
        tool_id = str(action.get("tool_id") or action.get("signature_id") or action_name)

        return DecisionRequest(
            tool_id=tool_id,
            action_name=action_name,
            method=method,
            path=path,
            host=host,
            params=params or {},
            toolset_name=self.toolset_name,
            confirmation_token_id=confirmation_token,
            source="enforce",
            mode=mode,
        )

    def evaluate_action(
        self,
        action_name: str,
        params: dict[str, Any] | None = None,
        confirmation_token: str | None = None,
        mode: str = "evaluate",
    ) -> dict[str, Any]:
        """Evaluate an action request using DecisionEngine."""
        request = self._build_decision_request(action_name, params, confirmation_token, mode=mode)
        if request is None:
            return {
                "decision": DecisionType.DENY.value,
                "allowed": False,
                "error": f"Unknown action: {action_name}",
                "reason_code": ReasonCode.DENIED_UNKNOWN_ACTION.value,
            }

        result = self.decision_engine.evaluate(request, self.decision_context)
        payload = self._decision_to_payload(result)

        if result.decision == DecisionType.CONFIRM and result.confirmation_token_id:
            click.echo(
                f"[mcpmint] Confirmation required for {action_name}. "
                f"Run: mcpmint confirm grant {result.confirmation_token_id}",
                err=True,
            )

        return payload

    def confirm_action(self, token: str) -> dict[str, Any]:
        """Grant a pending action token in the local confirmation store."""
        success = self.confirmation_store.grant(token)
        return {"confirmed": success, "token": token}

    def deny_action(self, token: str, reason: str | None = None) -> dict[str, Any]:
        """Deny a pending action token in the local confirmation store."""
        success = self.confirmation_store.deny(token, reason)
        return {"denied": success, "token": token, "reason": reason}

    def get_pending(self) -> list[dict[str, Any]]:
        """Get pending local confirmation challenges."""
        pending = self.confirmation_store.list_pending()
        enriched: list[dict[str, Any]] = []
        for item in pending:
            action = self.actions.get(item["tool_id"], {})
            method, path, host = self._resolve_action_endpoint(action) if action else ("", "", "")
            enriched.append(
                {
                    "token_id": item["token_id"],
                    "token": item["token_id"],
                    "action_id": action.get("name") or item["tool_id"],
                    "tool_id": item["tool_id"],
                    "method": method,
                    "path": path,
                    "host": host,
                    "expires_at": item["expires_at"],
                }
            )
        return enriched

    def execute_action(
        self,
        action_name: str,
        params: dict[str, Any] | None = None,
        confirmation_token: str | None = None,
    ) -> dict[str, Any]:
        """Execute an action with policy enforcement and upstream proxy."""
        eval_result = self.evaluate_action(
            action_name=action_name,
            params=params,
            confirmation_token=confirmation_token,
            mode="execute",
        )

        if not eval_result.get("allowed", False):
            return eval_result

        action = self.actions_by_name.get(action_name)
        if not action:
            return {
                "decision": DecisionType.DENY.value,
                "allowed": False,
                "error": f"Unknown action: {action_name}",
                "reason_code": ReasonCode.DENIED_UNKNOWN_ACTION.value,
            }

        if self.dry_run:
            return {
                "decision": DecisionType.ALLOW.value,
                "allowed": True,
                "dry_run": True,
                "action": action_name,
                "message": "Request would be sent (dry run mode)",
                "params": params,
            }

        try:
            response = asyncio.run(self._execute_upstream(action, params or {}))
            return {
                "decision": DecisionType.ALLOW.value,
                "allowed": True,
                "executed": True,
                "action": action_name,
                "response": response,
                "reason_code": ReasonCode.ALLOWED_POLICY.value,
            }
        except RuntimeBlockError as blocked:
            return {
                "decision": DecisionType.DENY.value,
                "allowed": False,
                "executed": False,
                "action": action_name,
                "reason_code": blocked.reason_code.value,
                "reason": blocked.message,
            }
        except Exception as e:
            return {
                "decision": DecisionType.DENY.value,
                "allowed": False,
                "executed": False,
                "action": action_name,
                "reason_code": ReasonCode.ERROR_INTERNAL.value,
                "error": str(e),
            }

    async def _get_http_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
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
        allowed_hosts = {str(h).lower() for h in self.tools_manifest.get("allowed_hosts", [])}
        if target_host.lower() == action_host.lower():
            return
        if target_host.lower() in allowed_hosts:
            return
        raise RuntimeBlockError(
            ReasonCode.DENIED_REDIRECT_NOT_ALLOWLISTED,
            f"Host '{target_host}' is not allowlisted for action host '{action_host}'",
        )

    async def _execute_upstream(
        self,
        action: dict[str, Any],
        params: dict[str, Any],
    ) -> dict[str, Any]:
        """Execute the upstream HTTP request."""
        method, path, action_host = self._resolve_action_endpoint(action)
        url = urljoin(self.base_url, path) if self.base_url else f"https://{action_host}{path}"

        for param_name, param_value in params.items():
            placeholder = f"{{{param_name}}}"
            if placeholder in url:
                url = url.replace(placeholder, str(param_value))

        headers: dict[str, str] = {"User-Agent": "MCPMint-Proxy/0.1"}
        if self.auth_header:
            headers["Authorization"] = self.auth_header

        request_kwargs: dict[str, Any] = {"headers": headers, "follow_redirects": False}
        if method.upper() in ("GET", "HEAD", "OPTIONS"):
            query_params = {
                k: v for k, v in params.items()
                if f"{{{k}}}" not in path
            }
            if query_params:
                request_kwargs["params"] = query_params
        else:
            body_params = {
                k: v for k, v in params.items()
                if f"{{{k}}}" not in path
            }
            if body_params:
                headers["Content-Type"] = "application/json"
                request_kwargs["json"] = body_params

        client = await self._get_http_client()
        current_url = url
        max_redirects = 3

        for _ in range(max_redirects + 1):
            parsed = urlparse(current_url)
            target_host = parsed.hostname or action_host
            self._validate_host_allowlist(target_host, action_host)
            self._validate_network_target(target_host)

            response = await client.request(method.upper(), current_url, **request_kwargs)
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
            if content_type and content_type.startswith("application/octet-stream"):
                raise RuntimeBlockError(
                    ReasonCode.DENIED_CONTENT_TYPE_NOT_ALLOWED,
                    f"Blocked response content type: {content_type}",
                )

            response_body: Any
            if "json" in content_type:
                try:
                    response_body = response.json()
                except json.JSONDecodeError:
                    response_body = response.text
            else:
                response_body = response.text

            self.audit_logger.log_enforce_decision(
                action_id=action.get("name"),
                endpoint_id=action.get("id"),
                method=method,
                path=path,
                host=target_host,
                decision="executed",
                rules_matched=[],
                caller_context={"proxy_status": response.status_code},
            )

            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response_body,
            }

        raise RuntimeBlockError(
            ReasonCode.DENIED_REDIRECT_NOT_ALLOWLISTED,
            "Maximum redirect hops exceeded",
        )


def create_handler(gateway: EnforcementGateway) -> type[BaseHTTPRequestHandler]:
    """Create HTTP request handler with gateway reference."""

    class GatewayHandler(BaseHTTPRequestHandler):
        """HTTP handler for enforcement gateway."""

        def _send_json(self, data: dict[str, Any], status: int = 200) -> None:
            body = json.dumps(data, indent=2).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_json(self) -> dict[str, Any]:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length == 0:
                return {}
            body = self.rfile.read(content_length)
            result: dict[str, Any] = json.loads(body.decode())
            return result

        def do_GET(self) -> None:
            parsed = urlparse(self.path)

            if parsed.path == "/health":
                self._send_json({"status": "ok"})
            elif parsed.path == "/pending":
                self._send_json({"pending": gateway.get_pending()})
            elif parsed.path == "/policy":
                self._send_json({
                    "name": gateway.policy_engine.policy.name,
                    "rules_count": len(gateway.policy_engine.policy.rules),
                    "default_action": gateway.policy_engine.policy.default_action.value,
                })
            elif parsed.path == "/actions":
                self._send_json({
                    "actions": list(gateway.actions_by_name.keys()),
                    "count": len(gateway.actions_by_name),
                })
            else:
                self._send_json({"error": "Not found"}, 404)

        def do_POST(self) -> None:
            parsed = urlparse(self.path)

            if parsed.path == "/evaluate":
                body = self._read_json()
                action_name = body.get("action")
                params = body.get("params", {})
                token = body.get("confirmation_token_id") or body.get("confirmation_token")

                if not action_name:
                    self._send_json({"error": "Missing 'action' field"}, 400)
                    return

                result = gateway.evaluate_action(action_name, params, token, mode="evaluate")
                status = 200 if result.get("allowed") else 403
                self._send_json(result, status)

            elif parsed.path == "/execute":
                if gateway.mode != "proxy":
                    self._send_json({
                        "error": "Execute endpoint only available in proxy mode. "
                                 "Use --mode=proxy to enable."
                    }, 400)
                    return

                body = self._read_json()
                action_name = body.get("action")
                params = body.get("params", {})
                token = body.get("confirmation_token_id") or body.get("confirmation_token")

                if not action_name:
                    self._send_json({"error": "Missing 'action' field"}, 400)
                    return

                result = gateway.execute_action(action_name, params, token)
                status = 200 if result.get("allowed") else 403
                self._send_json(result, status)

            elif parsed.path in {"/confirm", "/deny"}:
                self._send_json(
                    {
                        "error": "In-band confirmation is disabled. "
                                 "Use local CLI: mcpmint confirm grant|deny <token_id>",
                    },
                    410,
                )

            else:
                self._send_json({"error": "Not found"}, 404)

        def log_message(self, format: str, *args: Any) -> None:
            if gateway.verbose:
                click.echo(f"{self.address_string()} - {format % args}")

    return GatewayHandler


def run_enforce(
    tools_path: str,
    toolsets_path: str | None,
    toolset_name: str | None,
    policy_path: str,
    port: int,
    audit_log: str | None,
    dry_run: bool,
    verbose: bool,
    mode: str = "evaluate",
    base_url: str | None = None,
    auth_header: str | None = None,
    lockfile_path: str | None = None,
    confirmation_store_path: str = ".mcpmint/confirmations.db",
    allow_private_cidrs: list[str] | None = None,
    allow_redirects: bool = False,
    unsafe_no_lockfile: bool = False,
) -> None:
    """Run the enforce command."""
    if not Path(tools_path).exists():
        click.echo(f"Error: Tools file not found: {tools_path}", err=True)
        sys.exit(1)

    if not Path(policy_path).exists():
        click.echo(f"Error: Policy file not found: {policy_path}", err=True)
        sys.exit(1)

    if mode == "proxy" and not lockfile_path and not unsafe_no_lockfile:
        click.echo(
            "Error: Proxy mode requires --lockfile by default for approval/integrity gating. "
            "Use --unsafe-no-lockfile to bypass (not recommended).",
            err=True,
        )
        sys.exit(1)

    if mode == "proxy" and not lockfile_path and unsafe_no_lockfile:
        click.echo(
            "Warning: Proxy mode running without lockfile; approvals and integrity checks are disabled.",
            err=True,
        )

    if mode == "proxy" and not base_url:
        click.echo("Warning: Proxy mode without --base-url will use hosts from manifest", err=True)

    try:
        gateway = EnforcementGateway(
            tools_path=tools_path,
            policy_path=policy_path,
            toolsets_path=toolsets_path,
            toolset_name=toolset_name,
            audit_log=audit_log,
            dry_run=dry_run,
            verbose=verbose,
            mode=mode,
            base_url=base_url,
            auth_header=auth_header,
            lockfile_path=lockfile_path,
            confirmation_store_path=confirmation_store_path,
            allow_private_cidrs=allow_private_cidrs,
            allow_redirects=allow_redirects,
            unsafe_no_lockfile=unsafe_no_lockfile,
        )
    except Exception as e:
        click.echo(f"Error initializing gateway: {e}", err=True)
        sys.exit(1)

    handler = create_handler(gateway)
    server = HTTPServer(("0.0.0.0", port), handler)

    click.echo("\nEnforcement Gateway started")
    click.echo(f"  URL: http://localhost:{port}")
    click.echo(f"  Tools: {tools_path}")
    if toolset_name:
        click.echo(f"  Toolset: {toolset_name}")
        if toolsets_path:
            click.echo(f"  Toolsets: {toolsets_path}")
    click.echo(f"  Policy: {policy_path}")
    if lockfile_path:
        click.echo(f"  Lockfile: {lockfile_path}")
    click.echo(f"  Confirmation store: {confirmation_store_path}")
    if audit_log:
        click.echo(f"  Audit log: {audit_log}")
    if mode == "proxy":
        click.echo("  Mode: PROXY (requests forwarded to upstream)")
        if base_url:
            click.echo(f"  Base URL: {base_url}")
        if auth_header:
            click.echo("  Auth: [configured]")
    else:
        click.echo("  Mode: EVALUATE (policy only)")
    if dry_run:
        click.echo("  Dry run: ON (no actual execution)")

    click.echo("\nEndpoints:")
    click.echo("  GET  /health     - Health check")
    click.echo("  GET  /actions    - List available actions")
    click.echo("  GET  /policy     - Policy info")
    click.echo("  GET  /pending    - Pending local confirmations")
    click.echo("  POST /evaluate   - Evaluate action request")
    if mode == "proxy":
        click.echo("  POST /execute    - Execute action (evaluate + proxy)")
    click.echo("\nPress Ctrl+C to stop")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        click.echo("\nShutting down...")
        server.shutdown()
