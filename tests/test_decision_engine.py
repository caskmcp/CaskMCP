"""Tests for shared DecisionEngine governance behavior."""

from __future__ import annotations

from pathlib import Path

from mcpmint.core.approval import LockfileManager
from mcpmint.core.enforce import ConfirmationStore, DecisionEngine, PolicyEngine
from mcpmint.models.decision import DecisionContext, DecisionRequest
from mcpmint.models.policy import (
    MatchCondition,
    Policy,
    PolicyRule,
    RuleType,
    StateChangingOverride,
)


def _allow_all_policy() -> Policy:
    return Policy(
        name="allow_all",
        default_action=RuleType.DENY,
        rules=[
            PolicyRule(
                id="allow_all",
                name="Allow all",
                type=RuleType.ALLOW,
                priority=100,
                match=MatchCondition(),
            )
        ],
    )


def _manifest_action(method: str = "POST") -> dict[str, object]:
    return {
        "name": "create_user",
        "tool_id": "sig_create_user",
        "signature_id": "sig_create_user",
        "method": method,
        "path": "/api/users",
        "host": "api.example.com",
        "risk_tier": "medium",
    }


def _context(
    *,
    action: dict[str, object],
    policy: Policy,
    lockfile_manager: LockfileManager | None = None,
    artifacts_digest: str = "digest_current",
    lockfile_digest: str | None = None,
) -> DecisionContext:
    policy_engine = PolicyEngine(policy)
    return DecisionContext(
        manifest_view={
            "sig_create_user": action,
            "create_user": action,
        },
        policy=policy,
        policy_engine=policy_engine,
        lockfile=lockfile_manager,
        artifacts_digest_current=artifacts_digest,
        lockfile_digest_current=lockfile_digest,
    )


def test_write_requires_confirmation_and_grant_is_single_use(tmp_path: Path) -> None:
    store = ConfirmationStore(tmp_path / "confirmations.db")
    engine = DecisionEngine(store)
    action = _manifest_action("POST")
    context = _context(action=action, policy=_allow_all_policy())

    first = engine.evaluate(
        DecisionRequest(
            tool_id="sig_create_user",
            action_name="create_user",
            method="POST",
            path="/api/users",
            host="api.example.com",
            params={"name": "Jane"},
            mode="execute",
        ),
        context,
    )
    assert first.decision.value == "confirm"
    assert first.confirmation_token_id is not None

    assert store.grant(first.confirmation_token_id)

    second = engine.evaluate(
        DecisionRequest(
            tool_id="sig_create_user",
            action_name="create_user",
            method="POST",
            path="/api/users",
            host="api.example.com",
            params={"name": "Jane"},
            mode="execute",
            confirmation_token_id=first.confirmation_token_id,
        ),
        context,
    )
    assert second.decision.value == "allow"
    assert second.reason_code.value == "allowed_confirmation_granted"

    replay = engine.evaluate(
        DecisionRequest(
            tool_id="sig_create_user",
            action_name="create_user",
            method="POST",
            path="/api/users",
            host="api.example.com",
            params={"name": "Jane"},
            mode="execute",
            confirmation_token_id=first.confirmation_token_id,
        ),
        context,
    )
    assert replay.decision.value == "deny"
    assert replay.reason_code.value == "denied_confirmation_replay"


def test_integrity_mismatch_denies_before_policy(tmp_path: Path) -> None:
    store = ConfirmationStore(tmp_path / "confirmations.db")
    engine = DecisionEngine(store)
    action = _manifest_action("GET")
    policy = _allow_all_policy()

    lockfile_manager = LockfileManager(tmp_path / "mcpmint.lock.yaml")
    lockfile = lockfile_manager.load()
    lockfile.artifacts_digest = "expected_digest"

    context = _context(
        action=action,
        policy=policy,
        lockfile_manager=lockfile_manager,
        artifacts_digest="observed_digest",
    )

    result = engine.evaluate(
        DecisionRequest(
            tool_id="sig_create_user",
            action_name="create_user",
            method="GET",
            path="/api/users",
            host="api.example.com",
            mode="execute",
        ),
        context,
    )
    assert result.decision.value == "deny"
    assert result.reason_code.value == "denied_integrity_mismatch"


def test_state_changing_override_can_disable_step_up(tmp_path: Path) -> None:
    store = ConfirmationStore(tmp_path / "confirmations.db")
    engine = DecisionEngine(store)
    action = _manifest_action("POST")
    policy = _allow_all_policy()
    policy.state_changing_overrides = [
        StateChangingOverride(tool_id="sig_create_user", state_changing=False)
    ]
    context = _context(action=action, policy=policy)

    result = engine.evaluate(
        DecisionRequest(
            tool_id="sig_create_user",
            action_name="create_user",
            method="POST",
            path="/api/users",
            host="api.example.com",
            mode="execute",
        ),
        context,
    )
    assert result.decision.value == "allow"
    assert result.reason_code.value == "allowed_policy"
