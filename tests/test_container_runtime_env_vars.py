"""Tests for container runtime env var naming."""

from __future__ import annotations

import subprocess
from pathlib import Path

import yaml
from click.testing import CliRunner

from caskmcp.cli.main import cli
from caskmcp.core.runtime.container import emit_container_runtime
from caskmcp.core.toolpack import ToolpackContainerRuntime
from tests.helpers import write_demo_toolpack


def test_toolpack_container_default_env_allowlist_uses_caskmcp_prefix() -> None:
    runtime = ToolpackContainerRuntime(image="example:latest")
    assert runtime.env_allowlist == [
        "CASKMCP_TOOLPACK",
        "CASKMCP_TOOLSET",
        "CASKMCP_LOCKFILE",
        "CASKMCP_BASE_URL",
        "CASKMCP_AUTH_HEADER",
        "CASKMCP_AUDIT_LOG",
        "CASKMCP_DRY_RUN",
        "CASKMCP_CONFIRM_STORE",
        "CASKMCP_ALLOW_PRIVATE_CIDR",
        "CASKMCP_ALLOW_REDIRECTS",
    ]


def test_container_entrypoint_script_uses_caskmcp_env_vars(tmp_path: Path) -> None:
    runtime = ToolpackContainerRuntime(image="example:latest")
    files = emit_container_runtime(
        toolpack_dir=tmp_path / "toolpack",
        image=runtime.image,
        base_image=runtime.base_image,
        requirements_line="caskmcp==0.0.0",
        env_allowlist=runtime.env_allowlist,
        healthcheck_cmd=None,
        healthcheck_interval_s=10,
        healthcheck_timeout_s=5,
        healthcheck_retries=3,
        build=False,
    )

    entrypoint = files.entrypoint.read_text(encoding="utf-8")
    for var in runtime.env_allowlist:
        assert var in entrypoint


def test_run_container_sets_caskmcp_env_vars(tmp_path: Path, monkeypatch) -> None:
    toolpack_file = write_demo_toolpack(tmp_path)
    toolpack_dir = toolpack_file.parent

    payload = yaml.safe_load(toolpack_file.read_text()) or {}
    payload["runtime"] = {"mode": "container", "container": {"image": "caskmcp-toolpack:tp_demo"}}
    toolpack_file.write_text(yaml.safe_dump(payload, sort_keys=False))

    for name in ("Dockerfile", "entrypoint.sh", "caskmcp.run", "requirements.lock"):
        (toolpack_dir / name).write_text("stub\n")

    captured: dict[str, str] = {}

    def _fake_run(cmd, check, env, **kwargs):  # type: ignore[no-untyped-def]
        _ = (cmd, check, kwargs)
        captured.update({k: v for k, v in env.items() if k.startswith("CASKMCP_")})
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr("caskmcp.cli.run.docker_available", lambda: True)
    monkeypatch.setattr("caskmcp.cli.doctor.docker_available", lambda: True)
    monkeypatch.setattr("caskmcp.cli.run.subprocess.run", _fake_run)

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "--root",
            str(tmp_path),
            "run",
            "--toolpack",
            str(toolpack_file),
            "--runtime",
            "container",
            "--toolset",
            "readonly",
            "--lockfile",
            "/toolpack/lockfile/caskmcp.lock.yaml",
            "--base-url",
            "https://api.example.com",
            "--auth",
            "Bearer testtoken",
            "--audit-log",
            "audit.jsonl",
            "--dry-run",
            "--confirm-store",
            "confirmations.db",
            "--allow-private-cidr",
            "10.0.0.0/8",
            "--allow-private-cidr",
            "192.168.0.0/16",
            "--allow-redirects",
        ],
    )

    assert result.exit_code == 0
    assert captured["CASKMCP_TOOLPACK"] == "/toolpack/toolpack.yaml"
    assert captured["CASKMCP_TOOLSET"] == "readonly"
    assert captured["CASKMCP_LOCKFILE"] == "/toolpack/lockfile/caskmcp.lock.yaml"
    assert captured["CASKMCP_BASE_URL"] == "https://api.example.com"
    assert captured["CASKMCP_AUTH_HEADER"] == "Bearer testtoken"
    assert captured["CASKMCP_AUDIT_LOG"] == "audit.jsonl"
    assert captured["CASKMCP_DRY_RUN"] == "1"
    assert captured["CASKMCP_CONFIRM_STORE"] == "confirmations.db"
    assert captured["CASKMCP_ALLOW_PRIVATE_CIDR"] == "10.0.0.0/8 192.168.0.0/16"
    assert captured["CASKMCP_ALLOW_REDIRECTS"] == "1"

