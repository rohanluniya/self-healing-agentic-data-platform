"""Hypothesis property-based tests proving core Agentic SRE safety & grounding invariants."""

from __future__ import annotations

import tempfile
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from agentic_sre.config import Settings
from agentic_sre.correlator import IncidentCorrelator
from agentic_sre.lakehouse import IcebergEvidenceLakehouse
from agentic_sre.opa_policy import ALLOWLISTED_TOOLS, FORBIDDEN_TOOLS, OpaPolicyEngine
from agentic_sre.platform_model import (
    PlatformLineageGraph,
    PlatformStateStore,
    default_platform_assets,
)
from agentic_sre.rca import DeterministicRcaEngine
from agentic_sre.remediation import RemediationEngine
from ingestion.signal_generator import ALL_SCENARIOS, generate_scenario_signals
from services.pipeline.run_pipeline import run_end_to_end_pipeline

_policy = OpaPolicyEngine()


@settings(max_examples=40)
@given(
    tool_name=st.text(min_size=1, max_size=32).filter(lambda s: s.strip() not in ALLOWLISTED_TOOLS),
    role=st.sampled_from(["viewer", "operator", "approver", "admin"]),
    mode=st.sampled_from(["read_only", "guarded_active"]),
)
def test_property_unlisted_or_destructive_tools_always_denied(tool_name: str, role: str, mode: str) -> None:
    dec = _policy.evaluate(
        {
            "tool_name": tool_name,
            "phase": "execute",
            "agent_mode": mode,
            "actor_role": role,
            "approved": True,
            "dry_run_completed": True,
            "preconditions_passed": True,
            "idempotency_key": "prop-key",
            "verified_evidence_count": 5,
            "incident_is_false_positive": False,
            "parameters": {},
        }
    )
    assert dec.allow is False


@settings(max_examples=30)
@given(
    tool_name=st.sampled_from(sorted(FORBIDDEN_TOOLS)),
    evidence_cnt=st.integers(min_value=0, max_value=20),
)
def test_property_forbidden_tools_always_risk_forbidden(tool_name: str, evidence_cnt: int) -> None:
    dec = _policy.evaluate(
        {
            "tool_name": tool_name,
            "phase": "dry_run",
            "agent_mode": "guarded_active",
            "actor_role": "operator",
            "verified_evidence_count": evidence_cnt,
            "incident_is_false_positive": False,
            "parameters": {},
        }
    )
    assert dec.allow is False
    assert dec.risk_level == "forbidden"


@settings(max_examples=30)
@given(
    bad_retries=st.one_of(st.integers(min_value=-10, max_value=0), st.integers(min_value=4, max_value=500)),
    bad_partitions=st.one_of(st.integers(min_value=-10, max_value=0), st.integers(min_value=25, max_value=5000)),
)
def test_property_unbounded_retries_and_backfills_always_denied(bad_retries: int, bad_partitions: int) -> None:
    d_retry = _policy.evaluate(
        {
            "tool_name": "bounded_retry_task",
            "phase": "dry_run",
            "agent_mode": "guarded_active",
            "actor_role": "operator",
            "verified_evidence_count": 2,
            "incident_is_false_positive": False,
            "parameters": {"max_retries": bad_retries, "timeout_seconds": 120},
        }
    )
    assert d_retry.allow is False
    assert "retry_limit_exceeded" in d_retry.violations

    d_backfill = _policy.evaluate(
        {
            "tool_name": "backfill_partition",
            "phase": "dry_run",
            "agent_mode": "guarded_active",
            "actor_role": "operator",
            "verified_evidence_count": 2,
            "incident_is_false_positive": False,
            "parameters": {"partition_count": bad_partitions, "timeout_seconds": 300},
        }
    )
    assert d_backfill.allow is False
    assert "backfill_partition_limit_exceeded" in d_backfill.violations


@settings(max_examples=25)
@given(
    tool_name=st.sampled_from(sorted(ALLOWLISTED_TOOLS)),
    phase=st.sampled_from(["dry_run", "approve", "execute"]),
)
def test_property_false_positive_incidents_never_allowed_to_mutate(tool_name: str, phase: str) -> None:
    dec = _policy.evaluate(
        {
            "tool_name": tool_name,
            "phase": phase,
            "agent_mode": "guarded_active",
            "actor_role": "operator",
            "operator_id": "op-1",
            "approver_id": "appr-1",
            "approved": True,
            "dry_run_completed": True,
            "preconditions_passed": True,
            "idempotency_key": "fp-key",
            "asset_layer": "gold",
            "current_config_version": "v2.14.0",
            "last_known_good_version": "v2.13.4",
            "verified_evidence_count": 3,
            "incident_is_false_positive": True,
            "parameters": {"max_retries": 1, "partition_count": 1, "target_version": "v2.13.4", "timeout_seconds": 120},
        }
    )
    assert dec.allow is False
    assert "false_positive_incident_cannot_mutate" in dec.violations


@settings(max_examples=27)
@given(
    scenario=st.sampled_from(ALL_SCENARIOS),
    seed=st.integers(min_value=1, max_value=10_000),
)
def test_property_every_rca_citation_resolves_to_persisted_evidence(scenario: str, seed: int) -> None:
    lineage = PlatformLineageGraph()
    assets = default_platform_assets()
    correlator = IncidentCorrelator(lineage=lineage, assets_metadata=assets)
    rca = DeterministicRcaEngine(lineage=lineage, assets_metadata=assets)

    sigs = generate_scenario_signals(scenario, seed=seed)
    incs, sig_map = correlator.correlate(sigs)
    assert len(incs) == 1

    sig_ids = {s["signal_id"] for s in sigs}
    span_ids = {s["span_id"] for s in sigs}
    edge_ids = {e.edge_id for e in lineage.edges}
    commits = {s["commit_version"] for s in sigs if s.get("commit_version")}

    hyps = rca.diagnose_incident(incs[0], sig_map[incs[0].incident_id], sig_ids, span_ids, edge_ids, commits)
    for h in hyps:
        assert h.hallucinated_citation_count == 0
        assert h.verified_citation_count == h.total_citation_count
        assert all(p.verified for p in h.evidence_pointers)


@settings(max_examples=6, deadline=None)
@given(repeat_calls=st.integers(min_value=2, max_value=5))
def test_property_duplicate_idempotency_key_executes_at_most_once(repeat_calls: int) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = Settings(data_dir=Path(tmp) / "prop_data", agent_mode="read_only")
        cfg.ensure_dirs()
        run_end_to_end_pipeline(profile="smoke", seed=7, execute_demo_remediation=False, settings=cfg)
        lh = IcebergEvidenceLakehouse(cfg.warehouse_dir, cfg.catalog_db)
        st_store = PlatformStateStore(cfg.state_dir / "platform_state.json")
        engine = RemediationEngine(settings=cfg, lakehouse=lh, state_store=st_store)
        plan = next(p for p in engine.list_plans() if p.tool_name == "bounded_retry_task")
        approved = engine.approve_plan(plan_id=plan.plan_id, approver_id="appr-prop", approver_role="approver")
        first_res, first_replay = engine.execute_plan(
            plan_id=approved.plan_id,
            idempotency_key=approved.idempotency_key,
            operator_id="op-prop",
            operator_role="operator",
            agent_mode_override="guarded_active",
        )
        assert first_replay is False
        assert first_res.execution_count == 1
        for _ in range(repeat_calls - 1):
            res, is_replay = engine.execute_plan(
                plan_id=approved.plan_id,
                idempotency_key=approved.idempotency_key,
                operator_id="op-prop",
                operator_role="operator",
                agent_mode_override="guarded_active",
            )
            assert is_replay is True
            assert res.execution_count == 1
