"""FastAPI Self-Healing Data Platform Control Plane API (port 8060)."""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from fastapi import Depends, FastAPI, HTTPException, Response
from fastapi.responses import HTMLResponse

from agentic_sre.config import Settings, load_settings
from agentic_sre.correlator import IncidentCorrelator
from agentic_sre.lakehouse import IcebergEvidenceLakehouse
from agentic_sre.logging_utils import get_logger
from agentic_sre.opa_policy import OpaPolicyEngine
from agentic_sre.platform_model import PlatformLineageGraph, PlatformStateStore
from agentic_sre.quality import run_data_quality_suite, verify_audit_hash_chain
from agentic_sre.rca import DeterministicRcaEngine, OptionalLocalLLMAdapter
from agentic_sre.remediation import RemediationEngine, RemediationError
from agentic_sre.telemetry import DEFAULT_TELEMETRY
from ingestion.kafka_dlq_ingestor import DurableStreamIngestor
from ingestion.signal_generator import ALL_SCENARIOS, generate_scenario_signals
from models.schemas import (
    ApprovalRequest,
    CorrelatedIncidentModel,
    DryRunRequest,
    EvidenceBundleResponse,
    EvidencePointer,
    ExecuteRequest,
    PolicyDecisionModel,
    PolicyEvaluationRequest,
    RcaHypothesisModel,
    RollbackRequest,
    ScenarioInjectRequest,
)
from services.pipeline.run_pipeline import run_end_to_end_pipeline

# Import security module from current app directory safely under --app-dir or package import
API_DIR = Path(__file__).resolve().parent
if str(API_DIR) not in sys.path:
    sys.path.insert(0, str(API_DIR))

from security import Principal, require_roles  # noqa: E402

DASHBOARD_HTML = REPO_ROOT / "apps" / "sre-dashboard" / "index.html"


def _row_to_incident(row: dict[str, Any]) -> CorrelatedIncidentModel:
    return CorrelatedIncidentModel(
        incident_id=str(row["incident_id"]),
        title=str(row["title"]),
        scenario_type=str(row["scenario_type"]),
        root_asset_id=str(row["root_asset_id"]),
        impacted_assets=json.loads(row.get("impacted_assets_json") or "[]"),
        raw_alert_count=int(row["raw_alert_count"]),
        severity=str(row["severity"]),
        status=str(row["status"]),
        is_false_positive=bool(row.get("is_false_positive", False)),
        first_event_time_ms=int(row["first_event_time_ms"]),
        detected_at_ms=int(row["detected_at_ms"]),
        signal_ids=json.loads(row.get("signal_ids_json") or "[]"),
        span_ids=json.loads(row.get("span_ids_json") or "[]"),
        lineage_edges=json.loads(row.get("lineage_edges_json") or "[]"),
        commit_versions=json.loads(row.get("commit_versions_json") or "[]"),
        storm_compression_ratio=float(row.get("storm_compression_ratio") or 1.0),
        recommended_tool=str(row.get("recommended_tool") or "none_read_only"),
        recommended_parameters=json.loads(row.get("recommended_parameters_json") or "{}"),
    )


def _row_to_hypothesis(row: dict[str, Any]) -> RcaHypothesisModel:
    ptrs = [EvidencePointer(**p) for p in json.loads(row.get("evidence_pointers_json") or "[]")]
    return RcaHypothesisModel(
        hypothesis_id=str(row["hypothesis_id"]),
        incident_id=str(row["incident_id"]),
        rank=int(row["rank"]),
        root_asset_id=str(row["root_asset_id"]),
        root_cause_category=str(row["root_cause_category"]),
        confidence=float(row["confidence"]),
        rationale=str(row["rationale"]),
        recommended_tool=str(row["recommended_tool"]),
        recommended_parameters=json.loads(row.get("recommended_parameters_json") or "{}"),
        evidence_pointers=ptrs,
        verified_citation_count=int(row.get("verified_citation_count") or 0),
        total_citation_count=int(row.get("total_citation_count") or 0),
        hallucinated_citation_count=int(row.get("hallucinated_citation_count") or 0),
    )


def create_app(settings_override: Settings | None = None) -> FastAPI:
    app = FastAPI(
        title="Self-Healing Data Platform — Agentic SRE Control Plane",
        version="1.0.0",
        description="Evidence-grounded incident correlation, zero-hallucination RCA, OPA policy guardrails, and reversible remediations.",
    )

    def _cfg() -> Settings:
        cfg = settings_override or load_settings()
        cfg.ensure_dirs()
        return cfg

    def _components():
        cfg = _cfg()
        lh = IcebergEvidenceLakehouse(cfg.warehouse_dir, cfg.catalog_db)
        st = PlatformStateStore(cfg.state_dir / "platform_state.json")
        pol = OpaPolicyEngine(opa_policy_url=cfg.opa_policy_url, telemetry=DEFAULT_TELEMETRY)
        rem = RemediationEngine(
            settings=cfg, lakehouse=lh, state_store=st, policy_engine=pol, telemetry=DEFAULT_TELEMETRY
        )
        return cfg, lh, st, pol, rem

    # Bootstrap data lakehouse if completely empty so fresh server start is immediately populated
    cfg0 = _cfg()
    lh0 = IcebergEvidenceLakehouse(cfg0.warehouse_dir, cfg0.catalog_db)
    if lh0.read_arrow("bronze.telemetry_signals").num_rows == 0:
        run_end_to_end_pipeline(profile="local", seed=42, compact=True, settings=cfg0, telemetry=DEFAULT_TELEMETRY)

    logger = get_logger("agentic_sre.api", cfg0.logs_dir / "control_plane.jsonl")

    @app.get("/", response_class=HTMLResponse)
    def serve_dashboard() -> HTMLResponse:
        if DASHBOARD_HTML.exists():
            return HTMLResponse(content=DASHBOARD_HTML.read_text(encoding="utf-8"))
        return HTMLResponse("<h1>Self-Healing Agentic SRE Control Plane</h1>")

    @app.get("/health")
    def health() -> dict[str, Any]:
        cfg, lh, _, _, _ = _components()
        stats = lh.table_stats()
        return {
            "status": "ok",
            "service": "agentic-sre-control-plane",
            "runtime_mode": cfg.runtime_mode,
            "default_agent_mode": cfg.agent_mode,
            "opa_engine": "remote_opa_server" if cfg.opa_policy_url else "embedded_rego_v1",
            "optional_local_llm_enabled": cfg.enable_local_llm,
            "iceberg_tables_ready": len(stats),
            "timestamp": datetime.now(UTC).isoformat(),
        }

    @app.get("/metrics")
    def metrics() -> Response:
        return Response(content=DEFAULT_TELEMETRY.render_prometheus(), media_type="text/plain; version=0.0.4")

    @app.get("/v1/overview")
    def overview(principal: Principal = Depends(require_roles({"viewer", "operator", "approver"}))) -> dict[str, Any]:
        cfg, lh, st, _, rem = _components()
        analytics = lh.duckdb_analytics_summary()
        audit_rows = lh.read_rows("gold.remediation_audit_log")
        chain_ok, chain_msg = verify_audit_hash_chain(audit_rows)
        lineage = PlatformLineageGraph()
        dq_rows = lh.read_rows("quality.dq_results")
        return {
            "actor": {"id": principal.actor_id, "role": principal.role},
            "runtime_mode": cfg.runtime_mode,
            "default_agent_mode": cfg.agent_mode,
            "optional_local_llm_enabled": cfg.enable_local_llm,
            "freshness_utc": datetime.now(UTC).isoformat(),
            "analytics": analytics,
            "audit_chain": {"valid": chain_ok, "summary": chain_msg, "count": len(audit_rows)},
            "assets": [a.model_dump() for a in st.list_assets()],
            "lineage_edges": [e.model_dump() for e in lineage.edges],
            "dq_results": dq_rows,
            "iceberg_tables": lh.table_stats(),
            "plans": [p.model_dump() for p in rem.list_plans()],
            "recent_traces": DEFAULT_TELEMETRY.recent_traces(limit=12),
        }

    @app.get("/v1/incidents")
    def list_incidents(
        include_false_positives: bool = True,
        principal: Principal = Depends(require_roles({"viewer", "operator", "approver"})),
    ) -> dict[str, Any]:
        _, lh, _, _, _ = _components()
        rows = lh.read_rows("silver.correlated_incidents")
        incidents = [_row_to_incident(r) for r in rows]
        if not include_false_positives:
            incidents = [i for i in incidents if not i.is_false_positive]
        incidents.sort(key=lambda i: (i.is_false_positive, -i.detected_at_ms))
        return {
            "actor_role": principal.role,
            "count": len(incidents),
            "incidents": [i.model_dump() for i in incidents],
        }

    @app.get("/v1/incidents/{incident_id}/evidence", response_model=EvidenceBundleResponse)
    def get_incident_evidence(
        incident_id: str,
        principal: Principal = Depends(require_roles({"viewer", "operator", "approver"})),
    ) -> EvidenceBundleResponse:
        cfg, lh, _, _, _ = _components()
        inc_rows = [r for r in lh.read_rows("silver.correlated_incidents") if r["incident_id"] == incident_id]
        if not inc_rows:
            raise HTTPException(status_code=404, detail=f"Incident not found: {incident_id}")
        incident = _row_to_incident(inc_rows[0])

        hyp_rows = [r for r in lh.read_rows("gold.rca_hypotheses") if r["incident_id"] == incident_id]
        hyp_rows.sort(key=lambda r: int(r["rank"]))
        hypotheses = [_row_to_hypothesis(r) for r in hyp_rows]

        sig_id_set = set(incident.signal_ids)
        signals = [s for s in lh.read_rows("bronze.telemetry_signals") if s["signal_id"] in sig_id_set]

        lineage = PlatformLineageGraph()
        sub_edges = lineage.subgraph_edges(set(incident.impacted_assets))

        ver_cnt = sum(h.verified_citation_count for h in hypotheses)
        tot_cnt = sum(h.total_citation_count for h in hypotheses)
        hal_cnt = sum(h.hallucinated_citation_count for h in hypotheses)
        hal_rate = round((hal_cnt / tot_cnt) * 100.0, 4) if tot_cnt > 0 else 0.0

        llm_adapter = OptionalLocalLLMAdapter(
            enabled=cfg.enable_local_llm,
            base_url=cfg.ollama_base_url,
            model=cfg.ollama_model,
        )
        llm_summary = llm_adapter.summarize_verified_bundle(incident, hypotheses)

        logger.info(
            f"served_evidence_bundle incident={incident_id} role={principal.role}",
            extra={"correlation_id": incident_id, "component": "control_plane_api"},
        )
        return EvidenceBundleResponse(
            incident=incident,
            hypotheses=hypotheses,
            verified_evidence_count=ver_cnt,
            total_evidence_count=tot_cnt,
            hallucinated_evidence_rate=hal_rate,
            signals=signals,
            lineage_subgraph=sub_edges,
            optional_llm_summary=llm_summary,
        )

    @app.get("/v1/remediations")
    def list_remediations(
        principal: Principal = Depends(require_roles({"viewer", "operator", "approver"})),
    ) -> dict[str, Any]:
        _, _, _, _, rem = _components()
        plans = rem.list_plans()
        return {"actor_role": principal.role, "count": len(plans), "plans": [p.model_dump() for p in plans]}

    @app.post("/v1/remediations/dry-run")
    def propose_dry_run(
        req: DryRunRequest,
        principal: Principal = Depends(require_roles({"operator"})),
    ) -> dict[str, Any]:
        _, _, _, _, rem = _components()
        try:
            plan = rem.propose_dry_run(
                incident_id=req.incident_id,
                tool_name=req.tool_name,
                target_asset_id=req.target_asset_id,
                parameters=req.parameters,
                actor_id=principal.actor_id,
                actor_role=principal.role,
                idempotency_key=req.idempotency_key,
            )
            return {"plan": plan.model_dump()}
        except RemediationError as exc:
            raise HTTPException(
                status_code=exc.status_code,
                detail={
                    "error": str(exc),
                    "policy_decision": exc.policy_decision.model_dump() if exc.policy_decision else None,
                },
            ) from exc

    @app.post("/v1/remediations/{plan_id}/approve")
    def approve_remediation(
        plan_id: str,
        req: ApprovalRequest,
        principal: Principal = Depends(require_roles({"approver"})),
    ) -> dict[str, Any]:
        _, _, _, _, rem = _components()
        try:
            plan = rem.approve_plan(
                plan_id=plan_id,
                approver_id=principal.actor_id,
                approver_role=principal.role,
                comment=req.comment,
            )
            return {"plan": plan.model_dump()}
        except RemediationError as exc:
            raise HTTPException(
                status_code=exc.status_code,
                detail={
                    "error": str(exc),
                    "policy_decision": exc.policy_decision.model_dump() if exc.policy_decision else None,
                },
            ) from exc

    @app.post("/v1/remediations/{plan_id}/execute")
    def execute_remediation(
        plan_id: str,
        req: ExecuteRequest,
        principal: Principal = Depends(require_roles({"operator"})),
    ) -> dict[str, Any]:
        _, lh, st, _, rem = _components()
        try:
            plan, is_replay = rem.execute_plan(
                plan_id=plan_id,
                idempotency_key=req.idempotency_key,
                operator_id=principal.actor_id,
                operator_role=principal.role,
                agent_mode_override=req.agent_mode_override,
                simulate_post_check_failure=req.simulate_post_check_failure,
            )
            run_data_quality_suite(lh, f"post-exec-{plan.plan_id}", {a.asset_id for a in st.list_assets()})
            return {"plan": plan.model_dump(), "idempotent_replay": is_replay}
        except RemediationError as exc:
            raise HTTPException(
                status_code=exc.status_code,
                detail={
                    "error": str(exc),
                    "policy_decision": exc.policy_decision.model_dump() if exc.policy_decision else None,
                },
            ) from exc

    @app.post("/v1/remediations/{plan_id}/rollback")
    def rollback_remediation(
        plan_id: str,
        req: RollbackRequest,
        principal: Principal = Depends(require_roles({"operator"})),
    ) -> dict[str, Any]:
        _, lh, st, _, rem = _components()
        try:
            plan = rem.rollback_plan(
                plan_id=plan_id,
                operator_id=principal.actor_id,
                operator_role=principal.role,
                reason=req.reason,
            )
            run_data_quality_suite(lh, f"post-rb-{plan.plan_id}", {a.asset_id for a in st.list_assets()})
            return {"plan": plan.model_dump()}
        except RemediationError as exc:
            raise HTTPException(status_code=exc.status_code, detail={"error": str(exc)}) from exc

    @app.post("/v1/policy/evaluate", response_model=PolicyDecisionModel)
    def evaluate_policy(
        req: PolicyEvaluationRequest,
        principal: Principal = Depends(require_roles({"viewer", "operator", "approver"})),
    ) -> PolicyDecisionModel:
        _, _, st, pol, _ = _components()
        asset_tier = "tier0"
        asset_layer = "gold"
        cur_ver = ""
        lkg_ver = ""
        try:
            asset = st.get(req.target_asset_id)
            asset_tier = str(asset["tier"])
            asset_layer = str(asset["layer"])
            cur_ver = str(asset["current_config_version"])
            lkg_ver = str(asset["last_known_good_version"])
        except KeyError:
            pass
        return pol.evaluate(
            {
                "tool_name": req.tool_name,
                "phase": req.phase,
                "agent_mode": req.agent_mode,
                "actor_role": req.actor_role or principal.role,
                "operator_id": req.operator_id,
                "approver_id": req.approver_id,
                "approved": req.approved,
                "dry_run_completed": req.dry_run_completed,
                "preconditions_passed": req.preconditions_passed,
                "idempotency_key": req.idempotency_key,
                "asset_tier": asset_tier,
                "asset_layer": asset_layer,
                "current_config_version": cur_ver,
                "last_known_good_version": lkg_ver,
                "incident_is_false_positive": req.incident_is_false_positive,
                "verified_evidence_count": req.verified_evidence_count,
                "parameters": req.parameters,
            }
        )

    @app.get("/v1/audit")
    def get_audit_log(
        limit: int = 100,
        principal: Principal = Depends(require_roles({"viewer", "operator", "approver"})),
    ) -> dict[str, Any]:
        _, lh, _, _, _ = _components()
        rows = sorted(
            lh.read_rows("gold.remediation_audit_log"),
            key=lambda r: int(r.get("seq_no") or 0),
        )
        chain_ok, chain_msg = verify_audit_hash_chain(rows)
        return {
            "actor_role": principal.role,
            "chain_valid": chain_ok,
            "chain_summary": chain_msg,
            "total_entries": len(rows),
            "entries": list(reversed(rows[-limit:])),
        }

    @app.post("/v1/scenarios/inject")
    def inject_scenario(
        req: ScenarioInjectRequest,
        principal: Principal = Depends(require_roles({"operator"})),
    ) -> dict[str, Any]:
        if req.scenario not in ALL_SCENARIOS:
            raise HTTPException(status_code=400, detail=f"Unknown scenario '{req.scenario}'. Valid: {ALL_SCENARIOS}")
        cfg, lh, st, _, _ = _components()
        ingestor = DurableStreamIngestor(cfg.raw_stream_dir, telemetry=DEFAULT_TELEMETRY)
        now_ms = int(datetime.now(UTC).timestamp() * 1000)
        new_sigs = generate_scenario_signals(req.scenario, seed=req.seed, base_time_ms=now_ms)
        ingestor.publish(new_sigs, truncate=False)
        res = ingestor.consume(replay=False)
        lh.append("bronze.telemetry_signals", res.valid_signals)
        st.apply_signal_effects(res.valid_signals)

        assets_meta = {a.asset_id: st.get(a.asset_id) for a in st.list_assets()}
        lineage = PlatformLineageGraph()
        correlator = IncidentCorrelator(lineage=lineage, assets_metadata=assets_meta, telemetry=DEFAULT_TELEMETRY)
        new_incs, inc_sig_map = correlator.correlate(res.valid_signals)

        persisted_sigs = lh.read_rows("bronze.telemetry_signals")
        persisted_edges = lh.read_rows("silver.asset_lineage_graph")
        sig_ids = {str(r["signal_id"]) for r in persisted_sigs}
        span_ids = {str(r["span_id"]) for r in persisted_sigs}
        commits = {str(r["commit_version"]) for r in persisted_sigs if r.get("commit_version")}
        edge_ids = {str(r["edge_id"]) for r in persisted_edges}

        rca = DeterministicRcaEngine(lineage=lineage, assets_metadata=assets_meta, telemetry=DEFAULT_TELEMETRY)
        new_inc_rows = []
        new_hyp_rows = []
        for inc in new_incs:
            new_inc_rows.append(
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
            )
            for h in rca.diagnose_incident(inc, inc_sig_map[inc.incident_id], sig_ids, span_ids, edge_ids, commits):
                new_hyp_rows.append(
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
        lh.append("silver.correlated_incidents", new_inc_rows)
        lh.append("gold.rca_hypotheses", new_hyp_rows)
        return {
            "injected_by": principal.actor_id,
            "scenario": req.scenario,
            "signals_added": len(res.valid_signals),
            "incidents_created": [i.model_dump() for i in new_incs],
        }

    return app


app = create_app()
