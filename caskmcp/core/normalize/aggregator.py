"""Endpoint aggregation and deduplication."""

from __future__ import annotations

from collections import defaultdict
from typing import Any
from urllib.parse import urlparse

from caskmcp.core.normalize.path_normalizer import PathNormalizer, VarianceNormalizer
from caskmcp.models.capture import CaptureSession, HttpExchange
from caskmcp.models.endpoint import AuthType, Endpoint, Parameter, ParameterLocation


class EndpointAggregator:
    """Aggregate HTTP exchanges into normalized endpoints."""

    # Headers that indicate authentication
    AUTH_HEADERS = {
        "authorization": AuthType.BEARER,
        "x-api-key": AuthType.API_KEY,
        "x-auth-token": AuthType.BEARER,
        "cookie": AuthType.COOKIE,
    }

    # Path patterns that suggest auth-related endpoints
    AUTH_PATH_PATTERNS = (
        "/login",
        "/logout",
        "/signin",
        "/signout",
        "/auth",
        "/oauth",
        "/token",
        "/refresh",
        "/session",
        "/register",
        "/signup",
        "/password",
        "/reset",
        "/verify",
        "/confirm",
        "/2fa",
        "/mfa",
        "/otp",
    )

    # Field names that suggest PII
    PII_FIELDS = {
        "email",
        "phone",
        "ssn",
        "social_security",
        "address",
        "dob",
        "date_of_birth",
        "birthday",
        "name",
        "first_name",
        "last_name",
        "full_name",
        "credit_card",
        "card_number",
        "cvv",
        "passport",
        "license",
        "salary",
        "income",
    }

    def __init__(self, first_party_hosts: list[str] | None = None) -> None:
        """Initialize aggregator.

        Args:
            first_party_hosts: List of first-party host patterns
        """
        self.first_party_hosts = first_party_hosts or []
        self.path_normalizer = PathNormalizer()
        self.variance_normalizer = VarianceNormalizer(self.path_normalizer)

    def aggregate(self, session: CaptureSession) -> list[Endpoint]:
        """Aggregate a capture session into endpoints.

        Args:
            session: CaptureSession to aggregate

        Returns:
            List of aggregated Endpoint objects
        """
        # First pass: learn path patterns
        paths_by_method: dict[str, list[str]] = defaultdict(list)
        for exchange in session.exchanges:
            paths_by_method[exchange.method.value].append(exchange.path)

        for method, paths in paths_by_method.items():
            self.variance_normalizer.learn_from_paths(paths, method)

        # Second pass: group exchanges by normalized endpoint
        grouped: dict[tuple[str, str, str], list[HttpExchange]] = defaultdict(list)

        for exchange in session.exchanges:
            normalized_path = self.variance_normalizer.normalize_path(
                exchange.path, exchange.method.value
            )
            key = (exchange.method.value, exchange.host, normalized_path)
            grouped[key].append(exchange)

        # Create endpoints
        endpoints: list[Endpoint] = []
        for (method, host, path), exchanges in grouped.items():
            endpoint = self._create_endpoint(method, host, path, exchanges, session)
            endpoints.append(endpoint)

        # Canonical ordering keeps downstream artifacts deterministic.
        return sorted(
            endpoints,
            key=lambda ep: (ep.host, ep.method.upper(), ep.path, ep.signature_id),
        )

    def _create_endpoint(
        self,
        method: str,
        host: str,
        path: str,
        exchanges: list[HttpExchange],
        session: CaptureSession,
    ) -> Endpoint:
        """Create an Endpoint from grouped exchanges."""
        # Use first exchange as representative
        representative = exchanges[0]

        # Collect all observed data
        status_codes: set[int] = set()
        request_content_types: set[str] = set()
        response_content_types: set[str] = set()
        all_query_params: dict[str, set[str]] = defaultdict(set)
        request_body_samples: list[dict[str, Any]] = []
        response_body_samples: list[dict[str, Any]] = []

        for exchange in exchanges:
            if exchange.response_status:
                status_codes.add(exchange.response_status)
            if exchange.response_content_type:
                response_content_types.add(exchange.response_content_type.split(";")[0])

            # Extract query params
            parsed = urlparse(exchange.url)
            if parsed.query:
                for param in parsed.query.split("&"):
                    if "=" in param:
                        key, value = param.split("=", 1)
                        all_query_params[key].add(value)

            # Collect body samples (only dicts for schema inference)
            if exchange.request_body_json and isinstance(exchange.request_body_json, dict):
                request_body_samples.append(exchange.request_body_json)
            if exchange.response_body_json and isinstance(exchange.response_body_json, dict):
                response_body_samples.append(exchange.response_body_json)

        # Extract path parameters
        path_params = self._extract_path_params(path)

        # Build parameters list
        parameters: list[Parameter] = []

        for param_name in path_params:
            parameters.append(
                Parameter(
                    name=param_name,
                    location=ParameterLocation.PATH,
                    required=True,
                )
            )

        for param_name, values in all_query_params.items():
            param_type = self._infer_param_type(values)
            parameters.append(
                Parameter(
                    name=param_name,
                    location=ParameterLocation.QUERY,
                    param_type=param_type,
                    example=next(iter(values), None),
                )
            )

        # Detect auth
        auth_type, auth_header = self._detect_auth(representative)

        # Detect if auth-related endpoint
        is_auth_related = any(p in path.lower() for p in self.AUTH_PATH_PATTERNS)

        # Detect if has PII
        has_pii = self._detect_pii(request_body_samples, response_body_samples)

        # Determine if first-party
        is_first_party = self._is_first_party(host, session.allowed_hosts)

        # Infer request schema
        request_schema = None
        if request_body_samples:
            request_schema = self._infer_schema(request_body_samples)

        # Infer response schema
        response_schema = None
        if response_body_samples:
            response_schema = self._infer_schema(response_body_samples)

        # Determine risk tier
        risk_tier = self._determine_risk_tier(
            method=method,
            is_auth_related=is_auth_related,
            has_pii=has_pii,
            is_first_party=is_first_party,
        )

        return Endpoint(
            method=method,
            path=path,
            host=host,
            url=f"https://{host}{path}",
            parameters=parameters,
            request_content_type=next(iter(request_content_types), None),
            request_body_schema=request_schema,
            request_examples=request_body_samples[:3],  # Keep up to 3 examples
            response_status_codes=sorted(status_codes),
            response_content_type=next(iter(response_content_types), None),
            response_body_schema=response_schema,
            response_examples=response_body_samples[:3],
            auth_type=auth_type,
            auth_header=auth_header,
            is_first_party=is_first_party,
            is_state_changing=method in ("POST", "PUT", "PATCH", "DELETE"),
            is_auth_related=is_auth_related,
            has_pii=has_pii,
            risk_tier=risk_tier,
            first_seen=min((e.timestamp for e in exchanges if e.timestamp), default=None),
            last_seen=max((e.timestamp for e in exchanges if e.timestamp), default=None),
            observation_count=len(exchanges),
            exchange_ids=[e.id for e in exchanges],
        )

    def _extract_path_params(self, path: str) -> list[str]:
        """Extract parameter names from a path template."""
        params = []
        for segment in path.split("/"):
            if segment.startswith("{") and segment.endswith("}"):
                params.append(segment[1:-1])
        return params

    def _detect_auth(
        self, exchange: HttpExchange
    ) -> tuple[AuthType, str | None]:
        """Detect authentication type from exchange headers."""
        for header, auth_type in self.AUTH_HEADERS.items():
            if header in {h.lower() for h in exchange.request_headers}:
                # Get the actual header name (preserving case)
                actual_header = next(
                    (h for h in exchange.request_headers if h.lower() == header), None
                )
                return auth_type, actual_header

        return AuthType.NONE, None

    def _detect_pii(
        self,
        request_samples: list[dict[str, Any]],
        response_samples: list[dict[str, Any]],
    ) -> bool:
        """Detect if samples contain PII fields."""
        all_samples = request_samples + response_samples
        return any(self._has_pii_fields(sample) for sample in all_samples)

    def _has_pii_fields(self, obj: Any, depth: int = 0) -> bool:
        """Recursively check for PII field names."""
        if depth > 10:  # Prevent infinite recursion
            return False

        if isinstance(obj, dict):
            for key in obj:
                if key.lower() in self.PII_FIELDS:
                    return True
                if self._has_pii_fields(obj[key], depth + 1):
                    return True
        elif isinstance(obj, list):
            for item in obj:
                if self._has_pii_fields(item, depth + 1):
                    return True

        return False

    def _is_first_party(self, host: str, allowed_hosts: list[str]) -> bool:
        """Check if host is first-party."""
        import fnmatch

        for pattern in allowed_hosts or self.first_party_hosts:
            if pattern.startswith("*."):
                suffix = pattern[1:]
                if host == pattern[2:] or host.endswith(suffix):
                    return True
            elif fnmatch.fnmatch(host, pattern) or host == pattern:
                return True

        return bool(allowed_hosts or self.first_party_hosts)

    def _infer_param_type(self, values: set[str]) -> str:
        """Infer parameter type from observed values."""
        if not values:
            return "string"

        # Check if all values are numeric
        if all(v.isdigit() for v in values):
            return "integer"

        # Check if all values are boolean-like
        bool_values = {"true", "false", "1", "0", "yes", "no"}
        if all(v.lower() in bool_values for v in values):
            return "boolean"

        return "string"

    def _infer_schema(self, samples: list[dict[str, Any]]) -> dict[str, Any]:
        """Infer JSON schema from samples.

        This is a simplified schema inference. For production, consider
        using a more sophisticated approach.
        """
        if not samples:
            return {"type": "object"}

        # Collect all keys and their types
        properties: dict[str, dict[str, Any]] = {}

        for sample in samples:
            for key, value in sample.items():
                if key not in properties:
                    properties[key] = self._infer_type(value)

        return {
            "type": "object",
            "properties": properties,
        }

    def _infer_type(self, value: Any) -> dict[str, Any]:
        """Infer JSON schema type for a value."""
        if value is None:
            return {"type": "null"}
        if isinstance(value, bool):
            return {"type": "boolean"}
        if isinstance(value, int):
            return {"type": "integer"}
        if isinstance(value, float):
            return {"type": "number"}
        if isinstance(value, str):
            return {"type": "string"}
        if isinstance(value, list):
            if value:
                return {"type": "array", "items": self._infer_type(value[0])}
            return {"type": "array"}
        if isinstance(value, dict):
            return self._infer_schema([value])

        return {"type": "string"}

    def _determine_risk_tier(
        self,
        method: str,
        is_auth_related: bool,
        has_pii: bool,
        is_first_party: bool,
    ) -> str:
        """Determine risk tier for an endpoint."""
        if is_auth_related:
            return "critical"

        if method in ("DELETE",):
            return "high"

        if method in ("POST", "PUT", "PATCH"):
            if has_pii:
                return "high"
            return "medium"

        if has_pii:
            return "low"

        if not is_first_party:
            return "medium"

        return "safe"
