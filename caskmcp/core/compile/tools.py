"""Tool manifest generator for agent consumption."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from caskmcp.models.endpoint import Endpoint
from caskmcp.models.flow import FlowGraph
from caskmcp.models.scope import Scope
from caskmcp.utils.naming import generate_tool_name, resolve_collision
from caskmcp.utils.schema_version import CURRENT_SCHEMA_VERSION


class ToolManifestGenerator:
    """Generate tool manifests from endpoints for agent consumption."""

    # Risk tier to confirmation mapping
    CONFIRMATION_MAP = {
        "safe": "never",
        "low": "never",
        "medium": "on_risk",
        "high": "always",
        "critical": "always",
    }

    # Default rate limits by risk tier
    RATE_LIMIT_MAP = {
        "safe": 120,
        "low": 60,
        "medium": 30,
        "high": 10,
        "critical": 5,
    }

    def __init__(
        self,
        name: str = "Generated Tools",
        description: str | None = None,
        default_rate_limit: int | None = None,
    ) -> None:
        """Initialize the tool manifest generator.

        Args:
            name: Name for the tool manifest
            description: Optional description
            default_rate_limit: Default rate limit per minute
        """
        self.name = name
        self.description = description
        self.default_rate_limit = default_rate_limit

    def generate(
        self,
        endpoints: list[Endpoint],
        scope: Scope | None = None,
        capture_id: str | None = None,
        generated_at: datetime | None = None,
        flow_graph: FlowGraph | None = None,
    ) -> dict[str, Any]:
        """Generate a tool manifest from endpoints.

        Args:
            endpoints: List of endpoints to convert to actions
            scope: Optional scope that was applied
            capture_id: Optional capture session ID

        Returns:
            Tool manifest as dict
        """
        sorted_endpoints = sorted(
            endpoints,
            key=lambda ep: (ep.host, ep.method.upper(), ep.path, ep.signature_id),
        )

        # Collect unique hosts
        hosts = sorted({ep.host for ep in sorted_endpoints})

        # Generate actions with unique names
        actions = []
        used_names: set[str] = set()
        sig_to_name: dict[str, str] = {}

        for endpoint in sorted_endpoints:
            action = self._action_from_endpoint(endpoint, used_names)
            if scope:
                action["scopes"] = [scope.name]
            actions.append(action)
            sig_to_name[endpoint.signature_id] = action["name"]

        # Enrich with flow metadata (depends_on / enables)
        if flow_graph:
            self._apply_flow_metadata(actions, flow_graph, sig_to_name)

        manifest: dict[str, Any] = {
            "version": "1.0.0",
            "schema_version": CURRENT_SCHEMA_VERSION,
            "name": self.name,
            "generated_at": (generated_at or datetime.now(UTC)).isoformat(),
            "allowed_hosts": hosts,
            "actions": actions,
        }

        if self.description:
            manifest["description"] = self.description

        if capture_id:
            manifest["capture_id"] = capture_id

        if scope:
            manifest["scope"] = scope.name
            manifest["default_confirmation"] = (
                "always" if scope.confirmation_required else "on_risk"
            )
            if scope.rate_limit_per_minute:
                manifest["default_rate_limit"] = scope.rate_limit_per_minute

        if self.default_rate_limit:
            manifest["default_rate_limit"] = self.default_rate_limit

        return manifest

    def _action_from_endpoint(
        self,
        endpoint: Endpoint,
        used_names: set[str],
    ) -> dict[str, Any]:
        """Create an action from an endpoint.

        Args:
            endpoint: Endpoint to convert
            used_names: Set of already-used action names

        Returns:
            Action dict
        """
        # Generate unique name
        base_name = endpoint.tool_id or generate_tool_name(endpoint.method, endpoint.path)
        name = resolve_collision(base_name, used_names, endpoint.host)
        used_names.add(name)

        # Build input schema
        input_schema = self._build_input_schema(endpoint)

        # Build output schema
        output_schema = endpoint.response_body_schema

        # Determine confirmation requirement
        confirmation = self.CONFIRMATION_MAP.get(endpoint.risk_tier, "on_risk")
        if endpoint.is_state_changing and confirmation == "never":
            confirmation = "on_risk"

        # Determine rate limit
        rate_limit = self.RATE_LIMIT_MAP.get(endpoint.risk_tier, 30)

        action: dict[str, Any] = {
            "id": name,
            "tool_id": endpoint.signature_id,
            "name": name,
            "description": self._generate_description(endpoint),
            "endpoint_id": endpoint.stable_id,
            "signature_id": endpoint.signature_id,
            "method": endpoint.method,
            "path": endpoint.path,
            "host": endpoint.host,
            "input_schema": input_schema,
            "risk_tier": endpoint.risk_tier,
            "confirmation_required": confirmation,
            "rate_limit_per_minute": rate_limit,
            "tags": self._extract_tags(endpoint),
        }

        if output_schema:
            action["output_schema"] = output_schema

        return action

    def _build_input_schema(self, endpoint: Endpoint) -> dict[str, Any]:
        """Build JSON Schema for action input.

        Args:
            endpoint: Endpoint to build schema for

        Returns:
            JSON Schema dict
        """
        properties: dict[str, Any] = {}
        required: list[str] = []

        # Add parameters
        sorted_parameters = sorted(
            endpoint.parameters,
            key=lambda p: (p.location.value, p.name),
        )

        for param in sorted_parameters:
            prop: dict[str, Any] = {
                "type": param.param_type,
            }

            if param.description:
                prop["description"] = param.description
            if param.example is not None:
                prop["example"] = param.example
            if param.pattern:
                prop["pattern"] = param.pattern
            if param.default is not None:
                prop["default"] = param.default

            properties[param.name] = prop

            if param.required:
                required.append(param.name)

        # Add body schema properties if present
        if endpoint.request_body_schema:
            body_props = endpoint.request_body_schema.get("properties", {})
            body_required = endpoint.request_body_schema.get("required", [])

            for prop_name, prop_schema in body_props.items():
                if prop_name not in properties:
                    properties[prop_name] = prop_schema
                    if prop_name in body_required:
                        required.append(prop_name)

        schema: dict[str, Any] = {
            "type": "object",
            "properties": properties,
        }

        if required:
            schema["required"] = sorted(set(required))

        return schema

    def _generate_description(self, endpoint: Endpoint) -> str:
        """Generate an agent-friendly description for an action.

        Includes: verb + resource, path parameters, top response fields,
        risk warnings. Fixes pluralization issues.
        """
        method = endpoint.method.upper()
        path = endpoint.path

        # Extract resource name
        segments = [s for s in path.split("/") if s and not s.startswith("{")]
        resource = segments[-1].replace("_", " ").replace("-", " ") if segments else "resource"

        # Detect collection vs single resource
        is_collection = not path.rstrip("/").endswith("}")

        # Singularize for non-collection endpoints
        singular = self._singularize(resource)

        # Path parameter names
        path_params = [s[1:-1] for s in path.split("/") if s.startswith("{") and s.endswith("}")]

        # Build description
        if method == "GET":
            if is_collection:
                base = f"List all {resource}"
            elif path_params:
                base = f"Retrieve a {singular} by {{{path_params[-1]}}}"
            else:
                base = f"Retrieve {singular}"
        elif method == "POST":
            base = f"Create a new {singular}"
        elif method == "PUT":
            if path_params:
                base = f"Update a {singular} by {{{path_params[-1]}}}"
            else:
                base = f"Update {singular}"
        elif method == "PATCH":
            if path_params:
                base = f"Partially update a {singular} by {{{path_params[-1]}}}"
            else:
                base = f"Partially update {singular}"
        elif method == "DELETE":
            if path_params:
                base = f"Delete a {singular} by {{{path_params[-1]}}}"
            else:
                base = f"Delete {singular}"
        else:
            base = f"{method} {resource}"

        # Append top response fields
        fields_hint = self._response_fields_hint(endpoint)
        if fields_hint:
            base += f". Returns: {fields_hint}"

        # Add risk warning if needed
        if endpoint.risk_tier in ("high", "critical"):
            base += f" (Risk: {endpoint.risk_tier})"

        if endpoint.is_auth_related:
            base += " [Auth]"

        # Prepend "Use this to..." guidance based on domain tags
        guidance = self._tag_guidance(endpoint.tags)
        if guidance:
            base = f"Use this to {guidance}. {base}"

        return base

    def _apply_flow_metadata(
        self,
        actions: list[dict[str, Any]],
        flow_graph: FlowGraph,
        sig_to_name: dict[str, str],
    ) -> None:
        """Add depends_on / enables fields and dependency hints to actions."""
        name_to_action: dict[str, dict[str, Any]] = {a["name"]: a for a in actions}

        for edge in flow_graph.edges:
            source_name = sig_to_name.get(edge.source_id)
            target_name = sig_to_name.get(edge.target_id)
            if not source_name or not target_name:
                continue
            if source_name not in name_to_action or target_name not in name_to_action:
                continue

            # Source enables target
            source_action = name_to_action[source_name]
            source_action.setdefault("enables", [])
            if target_name not in source_action["enables"]:
                source_action["enables"].append(target_name)

            # Target depends on source
            target_action = name_to_action[target_name]
            target_action.setdefault("depends_on", [])
            if source_name not in target_action["depends_on"]:
                target_action["depends_on"].append(source_name)

            # Add dependency hint to target description
            desc = target_action.get("description", "")
            hint = f" (Call {source_name} first to obtain {edge.linking_field})"
            if hint not in desc:
                target_action["description"] = desc + hint

    # Domain tag -> guidance phrase
    _TAG_GUIDANCE_MAP: dict[str, str] = {
        "commerce": "browse or manage commerce data",
        "users": "access or manage user information",
        "auth": "handle authentication",
        "admin": "perform admin operations",
        "search": "search or query data",
        "content": "access or manage content",
        "notifications": "manage notifications or alerts",
    }

    def _tag_guidance(self, tags: list[str]) -> str:
        """Return a 'Use this to ...' guidance phrase based on domain tags."""
        for tag in tags:
            if tag in self._TAG_GUIDANCE_MAP:
                return self._TAG_GUIDANCE_MAP[tag]
        return ""

    @staticmethod
    def _singularize(word: str) -> str:
        """Naive singularization for resource names."""
        w = word.strip()
        if w.endswith("ies"):
            return w[:-3] + "y"
        if w.endswith("ses") or w.endswith("xes") or w.endswith("zes"):
            return w[:-2]
        if w.endswith("s") and not w.endswith("ss"):
            return w[:-1]
        return w

    @staticmethod
    def _response_fields_hint(endpoint: Endpoint, max_fields: int = 5) -> str:
        """Extract top response field names from schema."""
        schema = endpoint.response_body_schema
        if not schema or not isinstance(schema, dict):
            return ""
        props = schema.get("properties", {})
        if not props:
            return ""
        fields = list(props.keys())[:max_fields]
        return ", ".join(fields)

    def _extract_tags(self, endpoint: Endpoint) -> list[str]:
        """Extract tags from endpoint."""
        tags: list[str] = []

        # Extract from path
        segments = endpoint.path.strip("/").split("/")
        skip = {"api", "v1", "v2", "v3", "rest", "public", "private"}

        for segment in segments:
            if segment.lower() not in skip and not segment.startswith("{"):
                tags.append(segment)
                break

        # Add risk-based tags
        if endpoint.is_state_changing:
            tags.append("write")
        else:
            tags.append("read")

        if endpoint.is_auth_related:
            tags.append("auth")

        if endpoint.has_pii:
            tags.append("pii")

        return tags

    def to_json(self, manifest: dict[str, Any]) -> str:
        """Serialize manifest to JSON string.

        Args:
            manifest: Tool manifest dict

        Returns:
            JSON string
        """
        import json

        return json.dumps(manifest, indent=2)
