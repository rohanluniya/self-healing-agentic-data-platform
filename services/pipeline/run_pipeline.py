"""End-to-End Self-Healing Data Platform Pipeline Orchestrator (Bronze -> Silver -> Gold -> DQ -> Safe Dry-Run)."""

from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agentic_sre.config import Settings, load_settings
from agentic_sre.correlator import IncidentCorrelator
from agentic_sre.lakehouse import IcebergEvidenceLakehouse
from agentic_sre.logging_utils import get_logger
from agentic_sre.opa_policy import OpaPolicyEngine
from agentic_sre.platform_model import PlatformLineageGraph, PlatformStateStore
from agentic_sre.quality import run_data_quality_suite
from agentic_sre.rca import DeterministicRcaEngine
from agentic_sre.remediation import RemediationEngine
from agentic_sre.telemetry import DEFAULT_TELEMETRY, TelemetryHub
from ingestion.kafka_dlq_ingestor import DurableStreamIngestor
from ingestion.signal_generator import generate_platform_profile_batch


def run_end_to_end_pipeline(
    *,
    profile: str = "local",
    seed: int = 42,
    compact: bool = False,
    replay: bool = False,
    execute_demo_remediation: bool = True,
    settings: Settings | None = None,
    telemetry: TelemetryHub | None = None,
) -> dict[str, Any]:
    """Execute the complete vertical slice from deterministic generation through Iceberg V2, RCA, OPA, and DQ."""
    cfg = settings or load_settings()
    cfg.ensure_dirs()
    hub = telemetry or DEFAULT_TELEMETRY
    logger = get_logger("agentic_sre.pipeline", cfg.logs_dir / "control_plane.jsonl")
    run_id = f"run-{profile}-{seed}-{uuid.uuid4().hex[:8]}"
    t_start = time.perf_counter()

    with hub.start_span("pipeline.run_end_to_end", {"profile": profile, "seed": seed, "run_id": run_id}):
        lakehouse = IcebergEvidenceLakehouse(cfg.warehouse_dir, cfg.catalog_db)
        lineage = PlatformLineageGraph()
        state_store = PlatformStateStore(cfg.state_dir / "platform_state.json")
        state_store.reset()

        ingestor = DurableStreamIngestor(cfg.raw_stream_dir, telemetry=hub)
        if not replay:
            raw_batch = generate_platform_profile_batch(profile=profile, seed=seed)
            ingestor.publish(raw_batch, truncate=True)

        ingest_res = ingestor.consume(replay=True)

        # Persist Bronze tables + Silver Lineage Graph into Apache Iceberg V2
        lakehouse.overwrite("bronze.telemetry_signals", ingest_res.valid_signals)
        lakehouse.overwrite("bronze.quarantine_dlq", ingest_res.quarantined_records)
        lakehouse.overwrite(
            "silver.asset_lineage_graph",
            [e.model_dump() for e in lineage.edges],
        )

        # Reflect telemetry symptoms on fixture platform operational state
        state_store.apply_signal_effects(ingest_res.valid_signals)
        assets_meta = {a.asset_id: state_store.get(a.asset_id) for a in state_store.list_assets()}

        # Correlate incidents across lineage DAG & suppress false-positive noise
        correlator = IncidentCorrelator(lineage=lineage, assets_metadata=assets_meta, telemetry=hub)
        incidents, incident_signals_map = correlator.correlate(ingest_res.valid_signals)

        # Persist Silver Correlated Incidents
        incident_rows = [
            {
                "incident_id": inc.incident_id,
                "title": inc.title,
                "scenario_type": inc.scenario_type,
                "root_asset_id": inc.root_asset_id,
                "impacted_assets_json": json.dumps(inc.impacted_assets),
                "raw_alert_count": inc.raw_alert_count,
                "severity": inc.severity,
                "status": inc.status,
                "is_false_positive": inc.is_false_positive,
                "first_event_time_ms": inc.first_event_time_ms,
                "detected_at_ms": inc.detected_at_ms,
                "signal_ids_json": json.dumps(inc.signal_ids),
                "span_ids_json": json.dumps(inc.span_ids),
                "lineage_edges_json": json.dumps(inc.lineage_edges),
                "commit_versions_json": json.dumps(inc.commit_versions),
                "storm_compression_ratio": inc.storm_compression_ratio,
                "recommended_tool": inc.recommended_tool,
                "recommended_parameters_json": json.dumps(inc.recommended_parameters),
            }
            for inc in incidents
        ]
        lakehouse.overwrite("silver.correlated_incidents", incident_rows)

        # Read back persisted Iceberg V2 IDs so Zero-Hallucination Verifier validates against durable storage!
        persisted_sigs = lakehouse.read_rows("bronze.telemetry_signals")
        persisted_edges = lakehouse.read_rows("silver.asset_lineage_graph")
        persisted_sig_ids = {str(r["signal_id"]) for r in persisted_sigs}
        persisted_span_ids = {str(r["span_id"]) for r in persisted_sigs}
        persisted_commits = {str(r["commit_version"]) for r in persisted_sigs if r.get("commit_version")}
        persisted_edge_ids = {str(r["edge_id"]) for r in persisted_edges}

        rca_engine = DeterministicRcaEngine(lineage=lineage, assets_metadata=assets_meta, telemetry=hub)
        all_hypotheses_rows: list[dict[str, Any]] = []
        for inc in incidents:
            hyps = rca_engine.diagnose_incident(
                incident=inc,
                incident_signals=incident_signals_map[inc.incident_id],
                persisted_signal_ids=persisted_sig_ids,
                persisted_span_ids=persisted_span_ids,
                persisted_edge_ids=persisted_edge_ids,
                persisted_commits=persisted_commits,
                top_k=3,
            )
            for h in hyps:
                all_hypotheses_rows.append(
                    {
                        "hypothesis_id": h.hypothesis_id,
                        "incident_id": h.incident_id,
                        "rank": h.rank,
                        "root_asset_id": h.root_asset_id,
                        "root_cause_category": h.root_cause_category,
                        "confidence": h.confidence,
                        "rationale": h.rationale,
                        "recommended_tool": h.recommended_tool,
                        "recommended_parameters_json": json.dumps(h.recommended_parameters),
                        "evidence_pointers_json": json.dumps([p.model_dump() for p in h.evidence_pointers]),
                        "verified_citation_count": h.verified_citation_count,
                        "total_citation_count": h.total_citation_count,
                        "hallucinated_citation_count": h.hallucinated_citation_count,
                    }
                )
        lakehouse.overwrite("gold.rca_hypotheses", all_hypotheses_rows)

        # Reset plans & audit tables for clean reproducible pipeline runs, then create Dry-Run proposals for actionable incidents.
        lakehouse.overwrite("gold.remediation_plans", [])
        lakehouse.overwrite("gold.remediation_audit_log", [])

        policy_engine = OpaPolicyEngine(opa_policy_url=cfg.opa_policy_url, telemetry=hub)
        remediation_engine = RemediationEngine(
            settings=cfg,
            lakehouse=lakehouse,
            state_store=state_store,
            policy_engine=policy_engine,
            telemetry=hub,
        )

        created_plans: list[str] = []
        for inc in incidents:
            if inc.is_false_positive or inc.recommended_tool == "none_read_only":
                continue
            params = dict(inc.recommended_parameters)
            target_asset = str(params.pop("target_asset_id", inc.root_asset_id))
            plan = remediation_engine.propose_dry_run(
                incident_id=inc.incident_id,
                tool_name=inc.recommended_tool,
                target_asset_id=target_asset,
                parameters=params,
                actor_id="agent-planner",
                actor_role="operator",
            )
            created_plans.append(plan.plan_id)

        # Demonstrate one policy-approved, human-approved self-healing execution on stale MV so live dashboard shows full lifecycle!
        demo_executed_plan_id: str | None = None
        if execute_demo_remediation:
            for plan in remediation_engine.list_plans():
                if plan.tool_name == "rebuild_materialized_view":
                    approved = remediation_engine.approve_plan(
                        plan_id=plan.plan_id,
                        approver_id="sre-approver-01",
                        approver_role="approver",
                        comment="Verified stale MV evidence bundle; approved bounded refresh.",
                    )
                    remediation_engine.execute_plan(
                        plan_id=approved.plan_id,
                        idempotency_key=approved.idempotency_key,
                        operator_id="sre-operator-01",
                        operator_role="operator",
                        agent_mode_override="guarded_active",
                    )
                    demo_executed_plan_id = approved.plan_id
                    break

        # Run Data Quality checks over Iceberg V2 tables & audit hash chain
        dq_results = run_data_quality_suite(
            lakehouse=lakehouse,
            run_id=run_id,
            known_assets=set(assets_meta.keys()),
        )

        compaction_report: list[dict[str, Any]] = []
        if compact:
            for tbl in ("bronze.telemetry_signals", "gold.rca_hypotheses", "gold.remediation_audit_log"):
                compaction_report.append(lakehouse.compact_table(tbl))

        analytics = lakehouse.duckdb_analytics_summary()
        elapsed_ms = round((time.perf_counter() - t_start) * 1000.0, 2)

        summary: dict[str, Any] = {
            "run_id": run_id,
            "profile": profile,
            "seed": seed,
            "timestamp": datetime.now(UTC).isoformat(),
            "elapsed_ms": elapsed_ms,
            "ingestion": {
                "total_received": ingest_res.total_received,
                "valid_signals": len(ingest_res.valid_signals),
                "quarantined_dlq": len(ingest_res.quarantined_records),
                "duplicates_suppressed": ingest_res.duplicate_count,
                "retractions_processed": ingest_res.retraction_count,
            },
            "analytics": analytics,
            "plans_proposed": len(created_plans),
            "demo_executed_plan_id": demo_executed_plan_id,
            "dq_checks": dq_results,
            "dq_all_passed": all(c["passed"] for c in dq_results),
            "iceberg_tables": lakehouse.table_stats(),
            "compaction": compaction_report,
        }

        out_dir = REPO_ROOT / "results" / "pipeline"
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / f"pipeline_summary_{profile}.json").write_text(
            json.dumps(summary, indent=2), encoding="utf-8"
        )
        logger.info(
            f"pipeline_completed profile={profile} incidents={analytics['total_incidents']} dq_all_passed={summary['dq_all_passed']}",
            extra={"run_id": run_id, "component": "pipeline"},
        )
        return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Self-Healing Agentic Data Platform pipeline")
    parser.add_argument("--profile", choices=["smoke", "local", "stress"], default="local")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--compact", action="store_true")
    parser.add_argument("--replay", action="store_true")
    parser.add_argument("--no-demo-exec", action="store_true")
    args = parser.parse_args()

    result = run_end_to_end_pipeline(
        profile=args.profile,
        seed=args.seed,
        compact=args.compact,
        replay=args.replay,
        execute_demo_remediation=not args.no_demo_exec,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
