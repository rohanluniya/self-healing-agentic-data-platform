"""Unit tests verifying OPA Rego v1 policy guardrails across destructive tools, bounds, RBAC, and read-only mode."""

from __future__ import annotations

import pytest

from agentic_sre.opa_policy import FORBIDDEN_TOOLS, OpaPolicyEngine


@pytest.mark.parametrize("bad_tool", sorted(FORBIDDEN_TOOLS) + ["custom_sql_exec", "restart_prod_cluster"])
def test_forbidden_and_unlisted_tools_hard_denied(bad_tool: str) -> None:
    engine = OpaPolicyEngine()
    decision = engine.evaluate(
        {
            "tool_name": bad_tool,
            "phase": "dry_run",
            "agent_mode": "guarded_active",
            "actor_role": "operator",
            "asset_tier": "tier0",
            "asset_layer": "gold",
            "incident_is_false_positive": False,
            "verified_evidence_count": 3,
            "parameters": {},
        }
    )
    assert decision.allow is False
    assert len(decision.violations) >= 1


def test_read_only_mode_blocks_execution_even_when_approved() -> None:
    engine = OpaPolicyEngine()
    decision = engine.evaluate(
        {
            "tool_name": "rollback_config_version",
            "phase": "execute",
            "agent_mode": "read_only",
            "actor_role": "operator",
            "operator_id": "op-1",
            "approver_id": "appr-1",
            "enforce_sod": True,
            "approved": True,
            "dry_run_completed": True,
            "preconditions_passed": True,
            "idempotency_key": "idem-ro-1",
            "asset_tier": "tier0",
            "asset_layer": "silver",
            "current_config_version": "v2.14.0",
            "last_known_good_version": "v2.13.4",
            "incident_is_false_positive": False,
            "verified_evidence_count": 4,
            "parameters": {"target_version": "v2.13.4", "timeout_seconds": 180},
        }
    )
    assert decision.allow is False
    assert "read_only_mode_blocks_execution" in decision.violations


def test_separation_of_duties_enforced_when_operator_equals_approver() -> None:
    engine = OpaPolicyEngine()
    decision = engine.evaluate(
        {
            "tool_name": "rollback_config_version",
            "phase": "execute",
            "agent_mode": "guarded_active",
            "actor_role": "operator",
            "operator_id": "same-actor",
            "approver_id": "same-actor",
            "enforce_sod": True,
            "approved": True,
            "dry_run_completed": True,
            "preconditions_passed": True,
            "idempotency_key": "idem-sod-1",
            "asset_tier": "tier0",
            "asset_layer": "silver",
            "current_config_version": "v2.14.0",
            "last_known_good_version": "v2.13.4",
            "incident_is_false_positive": False,
            "verified_evidence_count": 4,
            "parameters": {"target_version": "v2.13.4", "timeout_seconds": 180},
        }
    )
    assert decision.allow is False
    assert "separation_of_duties_violation" in decision.violations


def test_bounded_approved_execution_allowed_in_guarded_active() -> None:
    engine = OpaPolicyEngine()
    decision = engine.evaluate(
        {
            "tool_name": "rollback_config_version",
            "phase": "execute",
            "agent_mode": "guarded_active",
            "actor_role": "operator",
            "operator_id": "op-1",
            "approver_id": "appr-1",
            "enforce_sod": True,
            "approved": True,
            "dry_run_completed": True,
            "preconditions_passed": True,
            "idempotency_key": "idem-ok-1",
            "asset_tier": "tier0",
            "asset_layer": "silver",
            "current_config_version": "v2.14.0",
            "last_known_good_version": "v2.13.4",
            "incident_is_false_positive": False,
            "verified_evidence_count": 4,
            "parameters": {"target_version": "v2.13.4", "timeout_seconds": 180},
        }
    )
    assert decision.allow is True
    assert decision.violations == []
