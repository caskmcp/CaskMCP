"""Redaction of sensitive data from captures."""

from __future__ import annotations

import re
from typing import Any

from caskmcp.models.capture import CaptureSession, HttpExchange


class Redactor:
    """Redact sensitive data from captured traffic."""

    # Headers to always redact
    SENSITIVE_HEADERS = {
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-access-token",
        "x-csrf-token",
        "x-xsrf-token",
        "proxy-authorization",
        "www-authenticate",
    }

    # Query param keys to redact
    SENSITIVE_PARAMS = {
        "token",
        "key",
        "api_key",
        "apikey",
        "api-key",
        "auth",
        "password",
        "secret",
        "signature",
        "session",
        "session_id",
        "sessionid",
        "access_token",
        "refresh_token",
    }

    # Patterns to redact from bodies
    SENSITIVE_PATTERNS = [
        # Bearer tokens
        (r"bearer\s+[a-zA-Z0-9\-_.]+", "[REDACTED_BEARER]"),
        # API keys in various formats
        (r"api[_-]?key[\"']?\s*[=:]\s*[\"']?[a-zA-Z0-9\-_]+", 'api_key="[REDACTED]"'),
        # Passwords
        (r"password[\"']?\s*[=:]\s*[\"']?[^\"'\s,}]+", 'password="[REDACTED]"'),
        # JWT tokens
        (r"eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+", "[REDACTED_JWT]"),
        # Basic auth
        (r"basic\s+[a-zA-Z0-9+/=]+", "[REDACTED_BASIC]"),
    ]

    # Compiled patterns
    _compiled_patterns: list[tuple[re.Pattern[str], str]] | None = None

    def __init__(
        self,
        extra_headers: set[str] | None = None,
        extra_params: set[str] | None = None,
        extra_patterns: list[tuple[str, str]] | None = None,
    ) -> None:
        """Initialize redactor with optional extra patterns.

        Args:
            extra_headers: Additional headers to redact
            extra_params: Additional query params to redact
            extra_patterns: Additional regex patterns to redact
        """
        self.headers = self.SENSITIVE_HEADERS.copy()
        if extra_headers:
            self.headers.update(extra_headers)

        self.params = self.SENSITIVE_PARAMS.copy()
        if extra_params:
            self.params.update(extra_params)

        patterns = list(self.SENSITIVE_PATTERNS)
        if extra_patterns:
            patterns.extend(extra_patterns)

        self._compiled_patterns = [
            (re.compile(p, re.IGNORECASE), r) for p, r in patterns
        ]

    def redact_session(self, session: CaptureSession) -> CaptureSession:
        """Redact all sensitive data from a capture session.

        Args:
            session: CaptureSession to redact

        Returns:
            New CaptureSession with redacted data
        """
        redacted_exchanges = [
            self.redact_exchange(exchange) for exchange in session.exchanges
        ]

        redacted_count = sum(len(e.redacted_fields) for e in redacted_exchanges)

        return CaptureSession(
            id=session.id,
            name=session.name,
            description=session.description,
            created_at=session.created_at,
            source=session.source,
            source_file=session.source_file,
            allowed_hosts=session.allowed_hosts,
            exchanges=redacted_exchanges,
            total_requests=session.total_requests,
            filtered_requests=session.filtered_requests,
            redacted_count=redacted_count,
            warnings=session.warnings,
        )

    def redact_exchange(self, exchange: HttpExchange) -> HttpExchange:
        """Redact sensitive data from a single exchange.

        Args:
            exchange: HttpExchange to redact

        Returns:
            New HttpExchange with redacted data
        """
        redacted_fields: list[str] = []

        # Redact request headers
        redacted_request_headers, header_redactions = self._redact_headers(
            exchange.request_headers
        )
        redacted_fields.extend(f"request_header:{h}" for h in header_redactions)

        # Redact response headers
        redacted_response_headers, header_redactions = self._redact_headers(
            exchange.response_headers
        )
        redacted_fields.extend(f"response_header:{h}" for h in header_redactions)

        # Redact URL query params
        redacted_url = self._redact_url(exchange.url)
        if redacted_url != exchange.url:
            redacted_fields.append("url")

        # Redact request body
        redacted_request_body = exchange.request_body
        redacted_request_body_json = exchange.request_body_json
        if exchange.request_body:
            redacted_request_body = self._redact_text(exchange.request_body)
            if redacted_request_body != exchange.request_body:
                redacted_fields.append("request_body")
        if exchange.request_body_json and isinstance(exchange.request_body_json, dict):
            redacted_request_body_json = self._redact_dict(exchange.request_body_json)

        # Redact response body
        redacted_response_body = exchange.response_body
        redacted_response_body_json = exchange.response_body_json
        if exchange.response_body:
            redacted_response_body = self._redact_text(exchange.response_body)
            if redacted_response_body != exchange.response_body:
                redacted_fields.append("response_body")
        if exchange.response_body_json and isinstance(exchange.response_body_json, dict):
            redacted_response_body_json = self._redact_dict(exchange.response_body_json)

        return HttpExchange(
            id=exchange.id,
            url=redacted_url,
            method=exchange.method,
            host=exchange.host,
            path=exchange.path,
            request_headers=redacted_request_headers,
            request_body=redacted_request_body,
            request_body_json=redacted_request_body_json,
            response_status=exchange.response_status,
            response_headers=redacted_response_headers,
            response_body=redacted_response_body,
            response_body_json=redacted_response_body_json,
            response_content_type=exchange.response_content_type,
            timestamp=exchange.timestamp,
            duration_ms=exchange.duration_ms,
            source=exchange.source,
            redacted_fields=redacted_fields,
            notes=exchange.notes,
        )

    def _redact_headers(
        self, headers: dict[str, str]
    ) -> tuple[dict[str, str], list[str]]:
        """Redact sensitive headers.

        Returns:
            Tuple of (redacted_headers, list of redacted header names)
        """
        redacted = {}
        redacted_names = []

        for name, value in headers.items():
            if name.lower() in self.headers:
                redacted[name] = "[REDACTED]"
                redacted_names.append(name)
            else:
                redacted[name] = value

        return redacted, redacted_names

    def _redact_url(self, url: str) -> str:
        """Redact sensitive query parameters from URL."""
        from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

        parsed = urlparse(url)
        if not parsed.query:
            return url

        params = parse_qs(parsed.query, keep_blank_values=True)
        redacted = {}
        changed = False

        for key, values in params.items():
            if key.lower() in self.params:
                redacted[key] = ["[REDACTED]"]
                changed = True
            else:
                redacted[key] = values

        if not changed:
            return url

        # Flatten single-value lists
        flat_params = {
            k: v[0] if len(v) == 1 else v for k, v in redacted.items()
        }
        new_query = urlencode(flat_params, doseq=True)

        return urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment,
            )
        )

    def _redact_text(self, text: str) -> str:
        """Redact sensitive patterns from text."""
        if not self._compiled_patterns:
            return text

        result = text
        for pattern, replacement in self._compiled_patterns:
            result = pattern.sub(replacement, result)

        return result

    def _redact_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        """Redact sensitive keys from a dictionary."""
        redacted: dict[str, Any] = {}

        for key, value in data.items():
            if key.lower() in self.params:
                redacted[key] = "[REDACTED]"
            elif isinstance(value, dict):
                redacted[key] = self._redact_dict(value)
            elif isinstance(value, list):
                redacted[key] = [
                    self._redact_dict(v) if isinstance(v, dict) else v for v in value
                ]
            elif isinstance(value, str):
                redacted[key] = self._redact_text(value)
            else:
                redacted[key] = value

        return redacted
