#!/usr/bin/env python3
"""Curate a scoped GitHub REST API OpenAPI spec for CaskMCP dogfooding.

Downloads the official GitHub OpenAPI spec from github/rest-api-description
at a pinned commit SHA, prunes paths to a small allowlist, and writes the
result to github-api-scoped.yaml.

Usage:
    python3 curate_spec.py              # Download and curate
    python3 curate_spec.py --refresh    # Re-download even if cached
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path
from urllib.request import urlopen

import yaml

# Pinned commit SHA for reproducibility
PINNED_SHA = "f710064757236b11a150543536a59c383344474a"
SPEC_URL = (
    f"https://raw.githubusercontent.com/github/rest-api-description/"
    f"{PINNED_SHA}/descriptions/api.github.com/api.github.com.yaml"
)

# Curated path allowlist -- covers repos, issues, pulls, commits, labels, user
ALLOWED_PATHS = {
    "/repos/{owner}/{repo}",
    "/repos/{owner}/{repo}/issues",
    "/repos/{owner}/{repo}/issues/{issue_number}",
    "/repos/{owner}/{repo}/issues/{issue_number}/comments",
    "/repos/{owner}/{repo}/pulls",
    "/repos/{owner}/{repo}/pulls/{pull_number}",
    "/repos/{owner}/{repo}/commits",
    "/repos/{owner}/{repo}/contents/{path}",
    "/repos/{owner}/{repo}/labels",
    "/user",
}

OUTPUT_DIR = Path(__file__).parent
OUTPUT_FILE = OUTPUT_DIR / "github-api-scoped.yaml"
CACHE_FILE = OUTPUT_DIR / ".full-spec-cache.yaml"


def download_spec(force: bool = False) -> dict:
    """Download the full GitHub OpenAPI spec (cached locally)."""
    if CACHE_FILE.exists() and not force:
        print(f"  Using cached spec: {CACHE_FILE}")
        return yaml.safe_load(CACHE_FILE.read_text())

    print(f"  Downloading spec from commit {PINNED_SHA[:12]}...")
    with urlopen(SPEC_URL) as resp:
        content = resp.read().decode("utf-8")

    CACHE_FILE.write_text(content)
    print(f"  Cached to: {CACHE_FILE}")
    return yaml.safe_load(content)


def curate(spec: dict) -> dict:
    """Prune paths to the allowlist, keep everything else intact."""
    original_path_count = len(spec.get("paths", {}))

    # Filter paths
    curated_paths = {}
    for path_key, path_item in spec.get("paths", {}).items():
        if path_key in ALLOWED_PATHS:
            curated_paths[path_key] = path_item

    spec["paths"] = curated_paths

    # Add metadata about curation
    spec.setdefault("info", {})
    spec["info"]["x-caskmcp-dogfood"] = {
        "pinned_sha": PINNED_SHA,
        "original_path_count": original_path_count,
        "curated_path_count": len(curated_paths),
        "allowed_paths": sorted(ALLOWED_PATHS),
    }

    return spec


def main() -> None:
    parser = argparse.ArgumentParser(description="Curate GitHub OpenAPI spec for dogfooding")
    parser.add_argument("--refresh", action="store_true", help="Re-download the spec")
    args = parser.parse_args()

    print("Curating GitHub REST API OpenAPI spec for CaskMCP dogfood\n")

    spec = download_spec(force=args.refresh)
    full_count = len(spec.get("paths", {}))
    print(f"  Full spec: {full_count} paths")

    curated = curate(spec)
    curated_count = len(curated["paths"])
    print(f"  Curated:   {curated_count} paths ({len(ALLOWED_PATHS)} path patterns)")

    # Count operations
    op_count = 0
    for path_item in curated["paths"].values():
        for method in ("get", "post", "put", "patch", "delete", "head"):
            if method in path_item:
                op_count += 1
    print(f"  Operations: {op_count}")

    # Write output
    with open(OUTPUT_FILE, "w") as f:
        yaml.dump(curated, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

    print(f"\n  Output: {OUTPUT_FILE}")
    print(f"  Pinned SHA: {PINNED_SHA}")
    print("\nDone.")


if __name__ == "__main__":
    main()
