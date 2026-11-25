"""Automated Chaos & Fault-Injection Drills (8 drills) persisting raw evidence to results/chaos/chaos_results.json."""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from agentic_sre.config import Settings
from agentic_sre.correlator import IncidentCorrelator
from agentic_sre.lakehouse import IcebergEvidenceLakehouse
from agentic_sre.platform_model import PlatformLineageGraph, PlatformStateStore
from agentic_sre.quality import verify_audit_hash_chain
from agentic_sre.rca import DeterministicRcaEngine
from agentic_sre.remediation import RemediationEngine, RemediationError
from ingestion.kafka_dlq_ingestor import DurableStreamIngestor
from ingestion.signal_generator import BASE_EPOCH_MS, generate_scenario_signals
from services.pipeline.run_pipeline import run_end_to_end_pipeline

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CHAOS_OUT = REPO_ROOT / "results" / "chaos" / "chaos_results.json"

_DRILL_RESULTS: list[dict[str, Any]] = []


def _record_drill(drill_id: str, title: str, passed: bool, elapsed_ms: float, evidence: dict[str, Any]) -> None:
    _DRILL_RESULTS.append(
        {
            "drill_id": drill_id,
            "title": title,
            "passed": passed,
            "elapsed_ms": round(elapsed_ms, 2),
            "evidence": evidence,
        }
    )


@pytest.fixture(scope="module", autouse=True)
def persist_chaos_report():
    _DRILL_RESULTS.clear()
    yield
    CHAOS_OUT.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "total_drills": len(_DRILL_RESULTS),
        "passed_drills": sum(1 for d in _DRILL_RESULTS if d["passed"]),
        "all_passed": all(d["passed"] for d in _DRILL_RESULTS) and len(_DRILL_RESULTS) >= 8,
        "drills": _DRILL_RESULTS,
    }
    CHAOS_OUT.write_text(json.dumps(report, indent=2), encoding="utf-8")


def test_drill_01_cascading_upstream_outage_incident_correlation() -> None:
    t0 = time.perf_counter()
    lineage = PlatformLineageGraph()
    sigs = generate_scenario_signals("upstream_broker_outage", seed=101)
    correlator = IncidentCorrelator(lineage=lineage)
    incs, sig_map = correlator.correlate(sigs)
    rca = DeterministicRcaEngine(lineage=lineage)
    hyps = rca.diagnose_incident(
        incs[0],
        sig_map[incs[0].incident_id],
        {s["signal_id"] for s in sigs},
        {s["span_id"] for s in sigs},
        {e.edge_id for e in lineage.edges},
        {s["commit_version"] for s in sigs if s.get("commit_version")},
    )
    ok = (
        len(incs) == 1
        and incs[0].raw_alert_count == 4
        and incs[0].root_asset_id == "kafka.payments_events"
        and hyps[0].hallucinated_citation_count == 0
    )
    _record_drill(
        "drill_01_cascading_upstream_outage",
        "Cascading 4-hop Kafka broker outage storm compressed to single upstream root cause",
        ok,
        (time.perf_counter() - t0) * 1000.0,
        {
            "raw_alerts": incs[0].raw_alert_count,
            "correlated_incidents": len(incs),
            "root_asset": incs[0].root_asset_id,
            "verified_citations": hyps[0].verified_citation_count,
        },
    )
    assert ok


def test_drill_02_bad_deploy_auto_rollback_on_failed_post_check(isolated_settings: Settings) -> None:
    t0 = time.perf_counter()
    run_end_to_end_pipeline(profile="smoke", seed=42, execute_demo_remediation=False, settings=isolated_settings)
    lh = IcebergEvidenceLakehouse(isolated_settings.warehouse_dir, isolated_settings.catalog_db)
    st = PlatformStateStore(isolated_settings.state_dir / "platform_state.json")
    engine = RemediationEngine(settings=isolated_settings, lakehouse=lh, state_store=st)

    plan = next(p for p in engine.list_plans() if p.tool_name == "rollback_config_version")
    pre_ver = st.get(plan.target_asset_id)["current_config_version"]
    appr = engine.approve_plan(plan_id=plan.plan_id, approver_id="chaos-approver", approver_role="approver")
    res, _ = engine.execute_plan(
        plan_id=appr.plan_id,
        idempotency_key=appr.idempotency_key,
        operator_id="chaos-operator",
        operator_role="operator",
        agent_mode_override="guarded_active",
        simulate_post_check_failure=True,
    )
    post_ver = st.get(plan.target_asset_id)["current_config_version"]
    audit_events = [a["event_type"] for a in lh.read_rows("gold.remediation_audit_log")]
    ok = (
        res.status == "ROLLED_BACK"
        and res.rollback_performed is True
        and post_ver == pre_ver
        and "POST_CHECK_FAILED" in audit_events
        and "AUTO_ROLLBACK_COMPLETED" in audit_events
    )
    _record_drill(
        "drill_02_auto_rollback_failed_post_check",
        "Automatic rollback triggered on failed post-action health check restores pre-action snapshot",
        ok,
        (time.perf_counter() - t0) * 1000.0,
        {"pre_version": pre_ver, "restored_version": post_ver, "status": res.status},
    )
    assert ok


def test_drill_03_unauthorized_and_unsafe_drop_table_opa_denial(isolated_settings: Settings) -> None:
    t0 = time.perf_counter()
    run_end_to_end_pipeline(profile="smoke", seed=42, execute_demo_remediation=False, settings=isolated_settings)
    lh = IcebergEvidenceLakehouse(isolated_settings.warehouse_dir, isolated_settings.catalog_db)
    st = PlatformStateStore(isolated_settings.state_dir / "platform_state.json")
    engine = RemediationEngine(settings=isolated_settings, lakehouse=lh, state_store=st)

    inc_id = lh.read_rows("silver.correlated_incidents")[0]["incident_id"]
    attempts = [
        ("drop_table", {}),
        ("delete_prod_data", {"where": "1=1"}),
        ("shell_exec", {"cmd": "rm -rf /"}),
        ("backfill_partition", {"partition_count": 500, "timeout_seconds": 300}),
    ]
    denied_count = 0
    for tool, params in attempts:
        with pytest.raises(RemediationError):
            engine.propose_dry_run(
                incident_id=inc_id,
                tool_name=tool,
                target_asset_id="gold.daily_revenue_mv",
                parameters=params,
                actor_id="chaos-op",
                actor_role="operator",
            )
        denied_count += 1

    ok = denied_count == len(attempts)
    _record_drill(
        "drill_03_opa_unsafe_action_denial",
        "OPA hard-denies drop_table, delete_prod_data, shell_exec, and unbounded 500-partition backfill",
        ok,
        (time.perf_counter() - t0) * 1000.0,
        {"unsafe_attempts": len(attempts), "denied": denied_count, "rejection_rate_pct": 100.0},
    )
    assert ok


def test_drill_04_duplicate_approval_and_execution_idempotency(isolated_settings: Settings) -> None:
    t0 = time.perf_counter()
    run_end_to_end_pipeline(profile="smoke", seed=42, execute_demo_remediation=False, settings=isolated_settings)
    lh = IcebergEvidenceLakehouse(isolated_settings.warehouse_dir, isolated_settings.catalog_db)
    st = PlatformStateStore(isolated_settings.state_dir / "platform_state.json")
    engine = RemediationEngine(settings=isolated_settings, lakehouse=lh, state_store=st)

    plan = next(p for p in engine.list_plans() if p.tool_name == "bounded_retry_task")
    # Duplicate approval calls
    a1 = engine.approve_plan(plan_id=plan.plan_id, approver_id="appr-1", approver_role="approver")
    a2 = engine.approve_plan(plan_id=plan.plan_id, approver_id="appr-1", approver_role="approver")
    # Triple execution calls with same idempotency_key
    r1, rep1 = engine.execute_plan(
        plan_id=a1.plan_id, idempotency_key=a1.idempotency_key, operator_id="op-1", operator_role="operator", agent_mode_override="guarded_active"
    )
    r2, rep2 = engine.execute_plan(
        plan_id=a1.plan_id, idempotency_key=a1.idempotency_key, operator_id="op-1", operator_role="operator", agent_mode_override="guarded_active"
    )
    r3, rep3 = engine.execute_plan(
        plan_id=a1.plan_id, idempotency_key=a1.idempotency_key, operator_id="op-1", operator_role="operator", agent_mode_override="guarded_active"
    )
    ok = (
        a1.status == a2.status == "APPROVED"
        and rep1 is False
        and rep2 is True
        and rep3 is True
        and r3.execution_count == 1
    )
    _record_drill(
        "drill_04_idempotent_approval_and_execution",
        "Duplicate approvals and 3x repeated execution calls execute mutation strictly once",
        ok,
        (time.perf_counter() - t0) * 1000.0,
        {"execute_calls": 3, "actual_executions": r3.execution_count, "replays_guarded": 2},
    )
    assert ok


def test_drill_05_false_positive_alert_storm_suppression(isolated_settings: Settings) -> None:
    t0 = time.perf_counter()
    run_end_to_end_pipeline(profile="smoke", seed=42, execute_demo_remediation=False, settings=isolated_settings)
    lh = IcebergEvidenceLakehouse(isolated_settings.warehouse_dir, isolated_settings.catalog_db)
    st = PlatformStateStore(isolated_settings.state_dir / "platform_state.json")
    engine = RemediationEngine(settings=isolated_settings, lakehouse=lh, state_store=st)

    fp_inc = next(i for i in lh.read_rows("silver.correlated_incidents") if i["is_false_positive"])
    blocked = False
    with pytest.raises(RemediationError):
        engine.propose_dry_run(
            incident_id=fp_inc["incident_id"],
            tool_name="pause_broken_pipeline",
            target_asset_id="bronze.orders_raw",
            parameters={"reason": "Attempted mutation on FP"},
            actor_id="chaos-op",
            actor_role="operator",
        )
        blocked = False
    blocked = True

    # Also test 5 distinct noisy warning spikes in isolation
    correlator = IncidentCorrelator()
    suppressed = 0
    for idx in range(5):
        sigs = generate_scenario_signals("false_positive_noisy_alert", seed=500 + idx, base_time_ms=BASE_EPOCH_MS + idx * 900_000)
        incs, _ = correlator.correlate(sigs)
        if len(incs) == 1 and incs[0].is_false_positive:
            suppressed += 1

    ok = blocked and suppressed == 5
    _record_drill(
        "drill_05_false_positive_suppression",
        "False-positive noisy alerts 100% suppressed and hard-blocked from mutating platform state",
        ok,
        (time.perf_counter() - t0) * 1000.0,
        {"noisy_spikes_tested": 5, "suppressed": suppressed, "fp_mutation_blocked": blocked},
    )
    assert ok


def test_drill_06_control_plane_state_loss_and_iceberg_rebuild(isolated_settings: Settings) -> None:
    t0 = time.perf_counter()
    run_end_to_end_pipeline(profile="smoke", seed=42, execute_demo_remediation=True, settings=isolated_settings)
    lh = IcebergEvidenceLakehouse(isolated_settings.warehouse_dir, isolated_settings.catalog_db)
    state_file = isolated_settings.state_dir / "platform_state.json"
    st_before = PlatformStateStore(state_file)
    mv_before = st_before.get("gold.daily_revenue_mv")

    # Simulate catastrophic local control-plane state loss
    state_file.unlink()
    assert not state_file.exists()

    # Rebuild operational state purely from durable Apache Iceberg V2 tables
    st_rebuilt = PlatformStateStore(state_file)
    engine = RemediationEngine(settings=isolated_settings, lakehouse=lh, state_store=st_rebuilt)
    rebuild_meta = engine.rebuild_platform_state_from_iceberg()
    mv_after = st_rebuilt.get("gold.daily_revenue_mv")

    ok = (
        rebuild_meta["rebuilt_from_iceberg"] is True
        and rebuild_meta["completed_plans_reapplied"] == 1
        and mv_after["status"] == mv_before["status"] == "healthy"
        and mv_after["freshness_lag_minutes"] == mv_before["freshness_lag_minutes"]
    )
    _record_drill(
        "drill_06_state_loss_iceberg_rebuild",
        "Control-plane operational state wiped and reconstructed identically from Apache Iceberg V2",
        ok,
        (time.perf_counter() - t0) * 1000.0,
        rebuild_meta,
    )
    assert ok


def test_drill_07_malformed_telemetry_dlq_quarantine_and_replay(tmp_path: Path) -> None:
    t0 = time.perf_counter()
    ingestor = DurableStreamIngestor(tmp_path / "chaos_stream")
    valid_sigs = generate_scenario_signals("schema_breakage", seed=88, include_duplicates=True, include_malformed=True)
    ingestor.publish(valid_sigs, truncate=True)
    # Inject raw corrupted JSON frame directly into durable stream log
    with ingestor.topic_file.open("a", encoding="utf-8") as fh:
        fh.write("{corrupted_json_frame_missing_quote\n")

    r1 = ingestor.consume(replay=False)
    r2 = ingestor.consume(replay=True)
    ok = (
        len(r1.valid_signals) == 5
        and len(r1.quarantined_records) == 2
        and r1.duplicate_count == 1
        and [s["signal_id"] for s in r2.valid_signals] == [s["signal_id"] for s in r1.valid_signals]
    )
    _record_drill(
        "drill_07_malformed_dlq_quarantine_replay",
        "Malformed JSON and invalid Avro payloads isolated to Quarantine DLQ with exact replay parity",
        ok,
        (time.perf_counter() - t0) * 1000.0,
        {"valid_ingested": len(r1.valid_signals), "quarantined_dlq": len(r1.quarantined_records), "duplicates_dropped": r1.duplicate_count},
    )
    assert ok


def test_drill_08_audit_log_tamper_detection(isolated_settings: Settings) -> None:
    t0 = time.perf_counter()
    run_end_to_end_pipeline(profile="smoke", seed=42, execute_demo_remediation=True, settings=isolated_settings)
    lh = IcebergEvidenceLakehouse(isolated_settings.warehouse_dir, isolated_settings.catalog_db)
    rows = lh.read_rows("gold.remediation_audit_log")

    valid_ok, _ = verify_audit_hash_chain(rows)
    tampered = [dict(r) for r in rows]
    tampered[0]["outcome"] = "FORGED_ALLOW"
    tamper_ok, tamper_msg = verify_audit_hash_chain(tampered)

    ok = valid_ok is True and tamper_ok is False
    _record_drill(
        "drill_08_audit_hash_chain_tamper_detection",
        "Cryptographic SHA-256 audit hash chain passes intact and detects single-field tampering",
        ok,
        (time.perf_counter() - t0) * 1000.0,
        {"entries_verified": len(rows), "intact_valid": valid_ok, "tampered_valid": tamper_ok, "tamper_reason": tamper_msg},
    )
    assert ok
