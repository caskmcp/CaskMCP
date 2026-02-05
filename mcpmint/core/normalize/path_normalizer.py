"""Path normalization for converting concrete paths to templates."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse


class PathNormalizer:
    """Normalize URL paths to templates with placeholders."""

    # UUID pattern
    UUID_PATTERN = re.compile(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        re.IGNORECASE,
    )

    # Numeric ID pattern (avoid matching version segments like v1, v2)
    NUMERIC_ID_PATTERN = re.compile(r"^(?!v\d+$)\d+$")

    # MongoDB ObjectId pattern (24 hex chars)
    OBJECTID_PATTERN = re.compile(r"^[0-9a-f]{24}$", re.IGNORECASE)

    # Base64-like tokens (long alphanumeric strings, typically > 20 chars)
    TOKEN_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{20,}$")

    # Email-like pattern
    EMAIL_PATTERN = re.compile(r"^[^@]+@[^@]+\.[^@]+$")

    def __init__(
        self,
        uuid_placeholder: str = "{uuid}",
        id_placeholder: str = "{id}",
        token_placeholder: str = "{token}",
        email_placeholder: str = "{email}",
        slug_placeholder: str = "{slug}",
    ) -> None:
        """Initialize normalizer with placeholder formats.

        Args:
            uuid_placeholder: Placeholder for UUIDs
            id_placeholder: Placeholder for numeric IDs
            token_placeholder: Placeholder for tokens
            email_placeholder: Placeholder for emails
            slug_placeholder: Placeholder for variable slugs
        """
        self.uuid_placeholder = uuid_placeholder
        self.id_placeholder = id_placeholder
        self.token_placeholder = token_placeholder
        self.email_placeholder = email_placeholder
        self.slug_placeholder = slug_placeholder

    def normalize(self, path: str) -> str:
        """Normalize a URL path to a template.

        Args:
            path: Raw URL path (e.g., /users/123/orders/abc-def-123)

        Returns:
            Normalized path template (e.g., /users/{id}/orders/{uuid})
        """
        if not path:
            return "/"

        # Handle query strings - normalize path only
        if "?" in path:
            path = path.split("?")[0]

        # Split into segments
        segments = path.split("/")
        normalized_segments: list[str] = []

        for segment in segments:
            if not segment:
                normalized_segments.append(segment)
                continue

            normalized = self._normalize_segment(segment)
            normalized_segments.append(normalized)

        return "/".join(normalized_segments) or "/"

    def normalize_url(self, url: str) -> tuple[str, str, str]:
        """Normalize a full URL and extract components.

        Args:
            url: Full URL

        Returns:
            Tuple of (host, normalized_path, normalized_full_path_with_method)
        """
        parsed = urlparse(url)
        host = parsed.netloc
        path = self.normalize(parsed.path)

        return host, path, f"{host}{path}"

    def _normalize_segment(self, segment: str) -> str:
        """Normalize a single path segment.

        Args:
            segment: A path segment

        Returns:
            Normalized segment (placeholder or original)
        """
        # Check patterns in order of specificity

        # UUID (most specific)
        if self.UUID_PATTERN.match(segment):
            return self.uuid_placeholder

        # MongoDB ObjectId
        if self.OBJECTID_PATTERN.match(segment):
            return self.id_placeholder

        # Numeric ID
        if self.NUMERIC_ID_PATTERN.match(segment):
            return self.id_placeholder

        # Email
        if self.EMAIL_PATTERN.match(segment):
            return self.email_placeholder

        # Long token-like strings
        if self.TOKEN_PATTERN.match(segment):
            return self.token_placeholder

        # Keep the original segment
        return segment

    def extract_parameters(
        self, template: str, path: str
    ) -> dict[str, str] | None:
        """Extract parameter values from a path given a template.

        Args:
            template: Path template (e.g., /users/{id})
            path: Actual path (e.g., /users/123)

        Returns:
            Dict of parameter names to values, or None if no match
        """
        template_segments = template.split("/")
        path_segments = path.split("/")

        if len(template_segments) != len(path_segments):
            return None

        params: dict[str, str] = {}

        for template_seg, path_seg in zip(template_segments, path_segments, strict=False):
            if template_seg.startswith("{") and template_seg.endswith("}"):
                param_name = template_seg[1:-1]
                params[param_name] = path_seg
            elif template_seg != path_seg:
                return None

        return params

    def matches_template(self, template: str, path: str) -> bool:
        """Check if a path matches a template.

        Args:
            template: Path template
            path: Actual path

        Returns:
            True if path matches template
        """
        return self.extract_parameters(template, path) is not None


class VarianceNormalizer:
    """Detect variable path segments by analyzing variance across samples."""

    def __init__(self, base_normalizer: PathNormalizer | None = None) -> None:
        """Initialize with optional base normalizer.

        Args:
            base_normalizer: PathNormalizer for initial normalization
        """
        self.normalizer = base_normalizer or PathNormalizer()
        self.templates: list[dict[str, Any]] = []

    def learn_from_paths(self, paths: list[str], method: str) -> None:
        """Learn path patterns from a set of paths.

        Args:
            paths: List of paths for the same method
            method: HTTP method
        """
        for path in paths:
            normalized = self.normalizer.normalize(path)
            segments = self._split_segments(normalized)

            template = self._find_matching_template(method, segments)
            if template is None:
                self.templates.append(
                    {
                        "method": method,
                        "length": len(segments),
                        "segments": list(segments),
                        "fixed": [True] * len(segments),
                    }
                )
            else:
                # Update template - mark varying segments
                for i, seg in enumerate(segments):
                    if template["fixed"][i] and template["segments"][i] != seg:
                        template["segments"][i] = "{slug}"
                        template["fixed"][i] = False

    def normalize_path(self, path: str, method: str) -> str:
        """Normalize a path using learned templates.

        Args:
            path: Path to normalize
            method: HTTP method

        Returns:
            Normalized path
        """
        normalized = self.normalizer.normalize(path)
        segments = self._split_segments(normalized)

        template = self._select_template(method, segments)
        if template is None:
            return "/" + "/".join(segments) if segments else "/"

        return "/" + "/".join(template["segments"]) if template["segments"] else "/"

    def _split_segments(self, path: str) -> list[str]:
        """Split path into non-empty segments."""
        return [s for s in path.split("/") if s]

    def _find_matching_template(
        self, method: str, segments: list[str]
    ) -> dict[str, Any] | None:
        """Find a template that matches the given segments."""
        for template in self.templates:
            if (
                template["method"] == method
                and template["length"] == len(segments)
                and self._segments_match(template, segments)
            ):
                return template
        return None

    def _select_template(
        self, method: str, segments: list[str]
    ) -> dict[str, Any] | None:
        """Select the best matching template for segments."""
        candidates = [
            t
            for t in self.templates
            if t["method"] == method
            and t["length"] == len(segments)
            and self._segments_match(t, segments)
        ]

        if not candidates:
            return None

        # Prefer template with most fixed segments
        return max(candidates, key=lambda t: sum(1 for f in t["fixed"] if f))

    def _segments_match(self, template: dict[str, Any], segments: list[str]) -> bool:
        """Check if segments match a template."""
        for i, segment in enumerate(segments):
            if i >= len(template["fixed"]):
                return False
            if template["fixed"][i] and template["segments"][i] != segment:
                return False
        return True
