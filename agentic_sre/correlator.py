"""Cross-Asset Lineage Incident Correlator & False-Positive Alert Suppression Engine."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from agentic_sre.contracts import compute_event_lag_seconds, deterministic_incident_id
from agentic_sre.platform_model import LAYER_ORDER, PlatformLineageGraph
from agentic_sre.telemetry import DEFAULT_TELEMETRY, TelemetryHub
from models.schemas import CorrelatedIncidentModel

CORRELATION_WINDOW_MS = 300_000  # 5-minute detection clustering window

SEVERITY_RANK = {"INFO": 0, "WARNING": 1, "ERROR": 2, "CRITICAL": 3}

HARD_CORROBORATING_TYPES = {
    "LOG_ERROR",
    "DQ_FAILURE",
    "TRACE_SPAN_ERROR",
    "AIRFLOW_TASK_EVENT",
    "SCHEMA_CONTRACT_ERROR",
    "BROKER_HEALTH_EVENT",
}


class IncidentCorrelator:
    """Deduplicates alert storms via OpenLineage DAG traversal and suppresses noisy false positives."""

    def __init__(
        self,
        lineage: PlatformLineageGraph | None = None,
        assets_metadata: dict[str, dict[str, Any]] | None = None,
        telemetry: TelemetryHub | None = None,
    ) -> None:
        self.lineage = lineage or PlatformLineageGraph()
        self.assets_metadata = assets_metadata or {}
        self.telemetry = telemetry or DEFAULT_TELEMETRY

    def correlate(self, signals: list[dict[str, Any]]) -> tuple[list[CorrelatedIncidentModel], dict[str, list[dict[str, Any]]]]:
        """Group raw telemetry signals into deduplicated root-cause incidents and map incident_id -> signals."""
        active_signals = [
            s
            for s in signals
            if not s.get("is_retraction", False)
            and (
                s.get("severity") in {"WARNING", "ERROR", "CRITICAL"}
                or s.get("signal_type") == "DEPLOYMENT_EVENT"
            )
        ]
        if not active_signals:
            return [], {}

        # Sort by processing_time_ms so late-arriving data still groups with the downstream drift alerts detected together.
        ordered = sorted(active_signals, key=lambda s: (int(s["processing_time_ms"]), str(s["signal_id"])))

        # Step 1: Temporal clustering into 5-minute correlation windows.
        windows: list[list[dict[str, Any]]] = []
        current_win: list[dict[str, Any]] = [ordered[0]]
        win_start = int(ordered[0]["processing_time_ms"])
        for sig in ordered[1:]:
            pt = int(sig["processing_time_ms"])
            if pt - win_start <= CORRELATION_WINDOW_MS:
                current_win.append(sig)
            else:
                windows.append(current_win)
                current_win = [sig]
                win_start = pt
        windows.append(current_win)

        incidents: list[CorrelatedIncidentModel] = []
        incident_signals: dict[str, list[dict[str, Any]]] = {}

        with self.telemetry.start_span("correlator.correlate", {"signal_count": len(active_signals)}):
            for win_idx, win_sigs in enumerate(windows):
                # Discard pure INFO-only windows (e.g., benign deployment with zero anomalies).
                non_info = [s for s in win_sigs if s.get("severity") != "INFO"]
                if not non_info:
                    continue

                asset_set = {str(s["asset_id"]) for s in win_sigs}
                components = self.lineage.connected_components(asset_set)

                for comp_assets in components:
                    comp_sigs = [s for s in win_sigs if str(s["asset_id"]) in comp_assets]
                    comp_non_info = [s for s in comp_sigs if s.get("severity") != "INFO"]
                    if not comp_non_info:
                        continue

                    incident = self._build_incident(comp_assets, comp_sigs, win_idx)
                    incidents.append(incident)
                    incident_signals[incident.incident_id] = comp_sigs

                    if incident.is_false_positive:
                        self.telemetry.false_positives_suppressed.inc()
                    self.telemetry.incidents_correlated.labels(
                        scenario_type=incident.scenario_type,
                        status=incident.status,
                    ).inc()

        active_count = sum(1 for inc in incidents if not inc.is_false_positive)
        self.telemetry.active_incidents_gauge.set(active_count)
        return incidents, incident_signals

    def _is_false_positive_noise(self, comp_sigs: list[dict[str, Any]]) -> bool:
        """Detect isolated single-sample transient metric warnings with zero corroborating failures."""
        non_info = [s for s in comp_sigs if s.get("severity") != "INFO"]
        if len(non_info) != 1:
            return False
        only = non_info[0]
        if only.get("severity") != "WARNING":
            return False
        if only.get("signal_type") != "METRIC_ANOMALY":
            return False
        if any(s.get("signal_type") in HARD_CORROBORATING_TYPES for s in comp_sigs):
            return False
        metric_name = str(only.get("metric_name") or "")
        metric_val = float(only.get("metric_value") or 0.0)
        if metric_name == "cost_multiplier" and metric_val >= 2.0:
            return False
        if metric_name == "freshness_lag_minutes":
            asset_meta = self.assets_metadata.get(str(only["asset_id"]), {})
            sla = float(asset_meta.get("sla_freshness_minutes", 30))
            if metric_val > sla:
                return False
        return True

    def _classify_asset_category(self, asset_id: str, asset_sigs: list[dict[str, Any]], all_sigs: list[dict[str, Any]]) -> tuple[str, float]:
        """Classify failure category for a candidate root asset and return (category, signal_specificity_score)."""
        types = {str(s["signal_type"]) for s in asset_sigs}
        messages = " ".join(str(s.get("message", "")).lower() for s in asset_sigs)
        metrics = {str(s.get("metric_name") or ""): float(s.get("metric_value") or 0.0) for s in asset_sigs if s.get("metric_name")}
        max_lag_s = max(
            (compute_event_lag_seconds(int(s["event_time_ms"]), int(s["processing_time_ms"])) for s in asset_sigs),
            default=0.0,
        )

        if "SCHEMA_CONTRACT_ERROR" in types or "schema incompatibility" in messages:
            return "schema_breakage", 6.5
        if "BROKER_HEALTH_EVENT" in types or "broker_not_available" in messages:
            return "upstream_broker_outage", 6.5
        if "DEPLOYMENT_EVENT" in types and any(s.get("severity") in {"ERROR", "CRITICAL"} for s in asset_sigs):
            return "bad_config_deployment", 6.0
        if "late_arrival_lag_minutes" in metrics or max_lag_s >= 1800.0 or "late-arriving" in messages:
            return "late_arriving_data", 5.8
        if "missing_partition_count" in metrics or "missing upstream" in messages or "missing partition" in messages:
            return "missing_upstream_partition", 5.6
        if metrics.get("cost_multiplier", 0.0) >= 2.0 or "partition skew" in messages or "cost spike" in messages:
            return "compute_cost_partition_skew", 5.5
        if "task_retry_count" in metrics or "retry storm" in messages or "503" in messages:
            return "transient_retry_storm", 5.4
        if "freshness_lag_minutes" in metrics or "stale" in messages:
            return "stale_table_sla_breach", 5.0
        # Fallback based on any deployment commit present across the component
        if any(s.get("signal_type") == "DEPLOYMENT_EVENT" for s in all_sigs):
            return "bad_config_deployment", 3.5
        return "pipeline_execution_failure", 3.0

    def _recommend_action(
        self,
        category: str,
        root_asset: str,
        comp_sigs: list[dict[str, Any]],
    ) -> tuple[str, str, dict[str, Any]]:
        """Map diagnosed root-cause category to (tool_name, target_asset_id, bounded_parameters)."""
        if category == "false_positive_noisy_alert":
            return "none_read_only", root_asset, {}

        if category in {"schema_breakage", "upstream_broker_outage"}:
            # Pause the immediate downstream bronze ingestion pipeline to prevent downstream corruption/retry storms.
            downstream = self.lineage.downstream.get(root_asset, [])
            target = downstream[0] if downstream else root_asset
            return (
                "pause_broken_pipeline",
                target,
                {
                    "reason": f"Contain upstream {category} originating at {root_asset}",
                    "timeout_seconds": 120,
                },
            )

        if category == "stale_table_sla_breach":
            return (
                "rebuild_materialized_view",
                root_asset,
                {"refresh_mode": "incremental_safe", "timeout_seconds": 300},
            )

        if category == "transient_retry_storm":
            return (
                "bounded_retry_task",
                root_asset,
                {"max_retries": 2, "backoff_seconds": 30, "timeout_seconds": 180},
            )

        if category == "bad_config_deployment":
            meta = self.assets_metadata.get(root_asset, {})
            target_ver = str(meta.get("last_known_good_version", "v2.13.4"))
            return (
                "rollback_config_version",
                root_asset,
                {"target_version": target_ver, "timeout_seconds": 180},
            )

        if category == "compute_cost_partition_skew":
            return (
                "pause_broken_pipeline",
                root_asset,
                {
                    "reason": f"Halt compute cost spike and partition skew on {root_asset}",
                    "timeout_seconds": 120,
                },
            )

        if category == "late_arriving_data":
            part = next((str(s["partition_key"]) for s in comp_sigs if s.get("partition_key")), "dt=2026-11-24/hr=08")
            downstream = self.lineage.downstream.get(root_asset, [])
            target = downstream[0] if downstream else root_asset
            return (
                "backfill_partition",
                target,
                {"partition_key": part, "partition_count": 1, "timeout_seconds": 300},
            )

        if category == "missing_upstream_partition":
            part = next((str(s["partition_key"]) for s in comp_sigs if s.get("partition_key")), "dt=2026-11-24/hr=14")
            return (
                "backfill_partition",
                root_asset,
                {"partition_key": part, "partition_count": 1, "timeout_seconds": 300},
            )

        return (
            "bounded_retry_task",
            root_asset,
            {"max_retries": 1, "backoff_seconds": 30, "timeout_seconds": 120},
        )

    def _build_incident(
        self,
        comp_assets: set[str],
        comp_sigs: list[dict[str, Any]],
        win_idx: int,
    ) -> CorrelatedIncidentModel:
        sigs_by_asset: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for s in comp_sigs:
            sigs_by_asset[str(s["asset_id"])].append(s)

        first_event_ms = min(int(s["event_time_ms"]) for s in comp_sigs)
        detected_at_ms = max(int(s["processing_time_ms"]) for s in comp_sigs)
        bucket_window = f"w{win_idx}-{detected_at_ms // CORRELATION_WINDOW_MS}"

        if self._is_false_positive_noise(comp_sigs):
            root_asset = next(iter(comp_assets))
            inc_id = deterministic_incident_id(root_asset, "false_positive_noisy_alert", bucket_window)
            return CorrelatedIncidentModel(
                incident_id=inc_id,
                title=f"[SUPPRESSED FP] Transient metric jitter on {root_asset}",
                scenario_type="false_positive_noisy_alert",
                root_asset_id=root_asset,
                impacted_assets=sorted(comp_assets),
                raw_alert_count=len(comp_sigs),
                severity="WARNING",
                status="suppressed_false_positive",
                is_false_positive=True,
                first_event_time_ms=first_event_ms,
                detected_at_ms=detected_at_ms,
                signal_ids=[str(s["signal_id"]) for s in comp_sigs],
                span_ids=[str(s["span_id"]) for s in comp_sigs],
                lineage_edges=[],
                commit_versions=[],
                storm_compression_ratio=1.0,
                recommended_tool="none_read_only",
                recommended_parameters={},
            )

        # Rank candidate root assets using upstream precedence + causal specificity + temporal precedence.
        scored: list[tuple[float, str, str]] = []
        for asset_id in sorted(comp_assets):
            ancestors_in_comp = self.lineage.ancestors(asset_id).intersection(comp_assets)
            asset_sigs = sigs_by_asset[asset_id]
            category, spec_score = self._classify_asset_category(asset_id, asset_sigs, comp_sigs)

            upstream_bonus = 4.5 if not ancestors_in_comp else -2.5 * len(ancestors_in_comp)
            asset_earliest = min(int(s["event_time_ms"]) for s in asset_sigs)
            temporal_bonus = 1.5 if asset_earliest == first_event_ms else 0.0
            layer_name = str(self.assets_metadata.get(asset_id, {}).get("layer", asset_id.split(".")[0]))
            layer_tiebreak = 0.1 * (5 - LAYER_ORDER.get(layer_name, 5))
            sev_bonus = 0.5 * max(SEVERITY_RANK.get(str(s["severity"]), 0) for s in asset_sigs)

            total = upstream_bonus + spec_score + temporal_bonus + layer_tiebreak + sev_bonus
            scored.append((total, asset_id, category))

        scored.sort(key=lambda x: (-x[0], x[1]))
        _, root_asset, scenario_type = scored[0]

        tool_name, target_asset, params = self._recommend_action(scenario_type, root_asset, comp_sigs)
        params_with_target = dict(params)
        params_with_target["target_asset_id"] = target_asset

        max_sev = max(
            (str(s["severity"]) for s in comp_sigs),
            key=lambda sv: SEVERITY_RANK.get(sv, 0),
        )
        sub_edges = [e.edge_id for e in self.lineage.subgraph_edges(comp_assets)]
        commits = sorted({str(s["commit_version"]) for s in comp_sigs if s.get("commit_version")})
        inc_id = deterministic_incident_id(root_asset, scenario_type, bucket_window)

        impacted_sorted = sorted(
            comp_assets,
            key=lambda a: (LAYER_ORDER.get(a.split(".")[0], 99), a),
        )
        raw_count = len(comp_sigs)

        return CorrelatedIncidentModel(
            incident_id=inc_id,
            title=f"{scenario_type.replace('_', ' ').title()} rooted at {root_asset}",
            scenario_type=scenario_type,
            root_asset_id=root_asset,
            impacted_assets=impacted_sorted,
            raw_alert_count=raw_count,
            severity=max_sev,
            status="open",
            is_false_positive=False,
            first_event_time_ms=first_event_ms,
            detected_at_ms=detected_at_ms,
            signal_ids=[str(s["signal_id"]) for s in comp_sigs],
            span_ids=[str(s["span_id"]) for s in comp_sigs],
            lineage_edges=sub_edges,
            commit_versions=commits,
            storm_compression_ratio=round(float(raw_count), 2),
            recommended_tool=tool_name,
            recommended_parameters=params_with_target,
        )
