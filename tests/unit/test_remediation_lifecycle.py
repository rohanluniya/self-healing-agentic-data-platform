"""Unit tests for the full remediation lifecycle: dry-run, approval, idempotent execution, auto-rollback, and audit chain."""

from __future__ import annotations

import pytest

from agentic_sre.config import Settings
from agentic_sre.lakehouse import IcebergEvidenceLakehouse
from agentic_sre.platform_model import PlatformStateStore
from agentic_sre.quality import verify_audit_hash_chain
from agentic_sre.remediation import RemediationEngine, RemediationError
from services.pipeline.run_pipeline import run_end_to_end_pipeline


def test_full_lifecycle_idempotency_and_manual_rollback(isolated_settings: Settings) -> None:
    run_end_to_end_pipeline(
        profile="smoke",
        seed=42,
        execute_demo_remediation=False,
        settings=isolated_settings,
    )
    lh = IcebergEvidenceLakehouse(isolated_settings.warehouse_dir, isolated_settings.catalog_db)
    st = PlatformStateStore(isolated_settings.state_dir / "platform_state.json")
    engine = RemediationEngine(settings=isolated_settings, lakehouse=lh, state_store=st)

    rollback_plan = next(p for p in engine.list_plans() if p.tool_name == "rollback_config_version")
    assert rollback_plan.status == "AWAITING_APPROVAL"

    # Execution before approval must be blocked by OPA!
    with pytest.raises(RemediationError):
        engine.execute_plan(
            plan_id=rollback_plan.plan_id,
            idempotency_key=rollback_plan.idempotency_key,
            operator_id="op-1",
            operator_role="operator",
            agent_mode_override="guarded_active",
        )

    # Human approver approves
    approved = engine.approve_plan(
        plan_id=rollback_plan.plan_id,
        approver_id="appr-1",
        approver_role="approver",
        comment="Verified evidence bundle",
    )
    assert approved.status == "APPROVED"

    # Execution in default read_only mode must still be blocked!
    with pytest.raises(RemediationError):
        engine.execute_plan(
            plan_id=approved.plan_id,
            idempotency_key=approved.idempotency_key,
            operator_id="op-1",
            operator_role="operator",
        )

    # Execute in guarded_active mode
    done, is_replay_1 = engine.execute_plan(
        plan_id=approved.plan_id,
        idempotency_key=approved.idempotency_key,
        operator_id="op-1",
        operator_role="operator",
        agent_mode_override="guarded_active",
    )
    assert is_replay_1 is False
    assert done.status == "COMPLETED"
    assert done.execution_count == 1
    assert st.get("silver.orders_enriched")["current_config_version"] == "v2.13.4"

    # Duplicate execution with same idempotency_key must NOT execute twice
    replayed_plan, is_replay_2 = engine.execute_plan(
        plan_id=approved.plan_id,
        idempotency_key=approved.idempotency_key,
        operator_id="op-1",
        operator_role="operator",
        agent_mode_override="guarded_active",
    )
    assert is_replay_2 is True
    assert replayed_plan.execution_count == 1

    # Manual rollback restores prior version v2.14.0
    rb = engine.rollback_plan(
        plan_id=done.plan_id,
        operator_id="op-1",
        operator_role="operator",
        reason="Operator verified rollback test",
    )
    assert rb.status == "ROLLED_BACK"
    assert rb.rollback_performed is True
    assert st.get("silver.orders_enriched")["current_config_version"] == "v2.14.0"

    # Verify SHA-256 hash chain integrity across all audit entries
    audit_rows = lh.read_rows("gold.remediation_audit_log")
    ok, _ = verify_audit_hash_chain(audit_rows)
    assert ok is True


def test_auto_rollback_on_failed_post_action_health_check(isolated_settings: Settings) -> None:
    run_end_to_end_pipeline(
        profile="smoke",
        seed=42,
        execute_demo_remediation=False,
        settings=isolated_settings,
    )
    lh = IcebergEvidenceLakehouse(isolated_settings.warehouse_dir, isolated_settings.catalog_db)
    st = PlatformStateStore(isolated_settings.state_dir / "platform_state.json")
    engine = RemediationEngine(settings=isolated_settings, lakehouse=lh, state_store=st)

    plan = next(p for p in engine.list_plans() if p.tool_name == "rollback_config_version")
    before_ver = st.get(plan.target_asset_id)["current_config_version"]
    approved = engine.approve_plan(plan_id=plan.plan_id, approver_id="appr-1", approver_role="approver")
    result, _ = engine.execute_plan(
        plan_id=approved.plan_id,
        idempotency_key=approved.idempotency_key,
        operator_id="op-1",
        operator_role="operator",
        agent_mode_override="guarded_active",
        simulate_post_check_failure=True,
    )
    assert result.status == "ROLLED_BACK"
    assert result.post_check_passed is False
    assert result.rollback_performed is True
    assert st.get(plan.target_asset_id)["current_config_version"] == before_ver
