"""CLI tests for compile command output-format surface."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import yaml
from click.testing import CliRunner

from caskmcp.cli.main import cli
from caskmcp.models.capture import CaptureSession, CaptureSource, HttpExchange, HTTPMethod
from caskmcp.storage import Storage


def _write_capture(tmp_path: Path) -> CaptureSession:
    session = CaptureSession(
        id="cap_compile",
        name="Compile Demo",
        source=CaptureSource.HAR,
        created_at=datetime(2026, 2, 6, tzinfo=UTC),
        allowed_hosts=["api.example.com"],
        exchanges=[
            HttpExchange(
                url="https://api.example.com/api/users",
                method=HTTPMethod.GET,
                host="api.example.com",
                path="/api/users",
                response_status=200,
                response_content_type="application/json",
            )
        ],
    )
    storage = Storage(base_path=tmp_path / ".caskmcp")
    storage.save_capture(session)
    return session


def _write_graphql_capture(tmp_path: Path) -> CaptureSession:
    session = CaptureSession(
        id="cap_compile_graphql",
        name="Compile GraphQL Demo",
        source=CaptureSource.HAR,
        created_at=datetime(2026, 2, 6, tzinfo=UTC),
        allowed_hosts=["api.example.com"],
        exchanges=[
            HttpExchange(
                url="https://api.example.com/api/graphql",
                method=HTTPMethod.POST,
                host="api.example.com",
                path="/api/graphql",
                request_body_json={
                    "operationName": "RecentlyViewedProducts",
                    "query": "query RecentlyViewedProducts($limit: Int!) { recentlyViewed(limit: $limit) { id } }",
                    "variables": {"limit": 1},
                },
                response_status=200,
                response_content_type="application/json",
                response_body_json={"data": {"recentlyViewed": [{"id": "p1"}]}},
            )
        ],
    )
    storage = Storage(base_path=tmp_path / ".caskmcp")
    storage.save_capture(session)
    return session


def _write_graphql_multi_operation_capture(tmp_path: Path) -> CaptureSession:
    session = CaptureSession(
        id="cap_compile_graphql_multi",
        name="Compile GraphQL Multi Demo",
        source=CaptureSource.HAR,
        created_at=datetime(2026, 2, 6, tzinfo=UTC),
        allowed_hosts=["api.example.com"],
        exchanges=[
            HttpExchange(
                url="https://api.example.com/api/graphql",
                method=HTTPMethod.POST,
                host="api.example.com",
                path="/api/graphql",
                request_body_json={
                    "operationName": "RecentlyViewedProducts",
                    "query": "query RecentlyViewedProducts($limit: Int!) { recentlyViewed(limit: $limit) { id } }",
                    "variables": {"limit": 1},
                },
                response_status=200,
                response_content_type="application/json",
                response_body_json={"data": {"recentlyViewed": [{"id": "p1"}]}},
            ),
            HttpExchange(
                url="https://api.example.com/api/graphql",
                method=HTTPMethod.POST,
                host="api.example.com",
                path="/api/graphql",
                request_body_json={
                    "operationName": "TrackEvent",
                    "query": "mutation TrackEvent($event: String!) { trackEvent(event: $event) { ok } }",
                    "variables": {"event": "click"},
                },
                response_status=200,
                response_content_type="application/json",
                response_body_json={"data": {"trackEvent": {"ok": True}}},
            ),
        ],
    )
    storage = Storage(base_path=tmp_path / ".caskmcp")
    storage.save_capture(session)
    return session


def test_compile_rejects_mcp_python_format() -> None:
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["compile", "--capture", "cap_dummy", "--format", "mcp-python"],
    )

    assert result.exit_code != 0
    assert "Invalid value for '--format' / '-f'" in result.stderr


def test_compile_manifest_format_still_works(tmp_path: Path, monkeypatch) -> None:
    session = _write_capture(tmp_path)
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        cli,
        [
            "compile",
            "--capture",
            session.id,
            "--scope",
            "first_party_only",
            "--format",
            "manifest",
            "--output",
            ".caskmcp/artifacts",
        ],
    )

    assert result.exit_code == 0
    assert "Compile complete:" in result.stdout
    artifacts_root = tmp_path / ".caskmcp" / "artifacts"
    artifact_dirs = [p for p in artifacts_root.iterdir() if p.is_dir()]
    assert artifact_dirs
    artifact_dir = artifact_dirs[0]
    assert (artifact_dir / "tools.json").exists()
    assert (artifact_dir / "toolsets.yaml").exists()
    assert (artifact_dir / "policy.yaml").exists()
    assert (artifact_dir / "baseline.json").exists()
    assert (artifact_dir / "contracts.yaml").exists()
    coverage_path = artifact_dir / "coverage_report.json"
    assert coverage_path.exists()
    payload = json.loads(coverage_path.read_text(encoding="utf-8"))
    assert payload["kind"] == "coverage_report"
    assert "precision" in payload["metrics"]
    assert "recall" in payload["metrics"]


def test_compile_coverage_report_uses_action_ids_for_graphql_ops(
    tmp_path: Path, monkeypatch
) -> None:
    session = _write_graphql_capture(tmp_path)
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        cli,
        [
            "compile",
            "--capture",
            session.id,
            "--scope",
            "first_party_only",
            "--format",
            "manifest",
            "--output",
            ".caskmcp/artifacts",
        ],
    )

    assert result.exit_code == 0
    artifacts_root = tmp_path / ".caskmcp" / "artifacts"
    artifact_dirs = [p for p in artifacts_root.iterdir() if p.is_dir()]
    assert artifact_dirs
    artifact_dir = artifact_dirs[0]

    tools = json.loads((artifact_dir / "tools.json").read_text(encoding="utf-8"))
    graphql_actions = [a for a in tools["actions"] if a["path"] == "/api/graphql"]
    assert len(graphql_actions) == 1
    graphql_action = graphql_actions[0]

    coverage = json.loads((artifact_dir / "coverage_report.json").read_text(encoding="utf-8"))
    candidates = coverage["candidates"]
    match = [c for c in candidates if c["tool_id"] == graphql_action["id"]]
    assert match, "Expected coverage report to reference the published GraphQL action id"
    assert match[0]["request_fingerprint"] == graphql_action["signature_id"]


def test_compile_scopes_suggestions_reference_published_graphql_action_signatures(
    tmp_path: Path, monkeypatch
) -> None:
    session = _write_graphql_multi_operation_capture(tmp_path)
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        cli,
        [
            "compile",
            "--capture",
            session.id,
            "--scope",
            "first_party_only",
            "--format",
            "manifest",
            "--output",
            ".caskmcp/artifacts",
        ],
    )

    assert result.exit_code == 0
    artifacts_root = tmp_path / ".caskmcp" / "artifacts"
    artifact_dirs = [p for p in artifacts_root.iterdir() if p.is_dir()]
    assert artifact_dirs
    artifact_dir = artifact_dirs[0]

    tools = json.loads((artifact_dir / "tools.json").read_text(encoding="utf-8"))
    graphql_actions = [a for a in tools["actions"] if a["path"] == "/api/graphql"]
    assert len(graphql_actions) == 2
    query_actions = [a for a in graphql_actions if "read" in (a.get("tags") or [])]
    mutation_actions = [a for a in graphql_actions if "write" in (a.get("tags") or [])]
    assert len(query_actions) == 1
    assert len(mutation_actions) == 1

    query_action = query_actions[0]
    mutation_action = mutation_actions[0]

    scope_suggestions = yaml.safe_load((artifact_dir / "scopes.suggested.yaml").read_text(encoding="utf-8"))
    drafts = scope_suggestions.get("drafts") or []

    # Drafts should reference published action signature IDs (post GraphQL operation splitting),
    # not the raw endpoint signature for /api/graphql.
    by_id = {d.get("endpoint_id"): d for d in drafts if isinstance(d, dict)}
    assert query_action["signature_id"] in by_id
    assert mutation_action["signature_id"] in by_id

    assert by_id[query_action["signature_id"]]["scope_name"] == "read"
    assert by_id[mutation_action["signature_id"]]["scope_name"] == "write"
