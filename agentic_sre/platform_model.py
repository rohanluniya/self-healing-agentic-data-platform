"""Fixture Data Platform Topology, OpenLineage Graph, and Mutable Operational State."""

from __future__ import annotations

import copy
import json
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

from models.schemas import AssetNodeModel, LineageEdgeModel

REPO_ROOT = Path(__file__).resolve().parent.parent
LINEAGE_FILE = REPO_ROOT / "schemas" / "openlineage" / "platform_lineage_events.json"

LAYER_ORDER = {
    "kafka": 0,
    "bronze": 1,
    "silver": 2,
    "gold": 3,
    "consumer": 4,
}


def default_platform_assets() -> dict[str, dict[str, Any]]:
    """Return canonical fixture data platform assets across Kafka -> Bronze -> Silver -> Gold -> Consumers."""
    assets: list[dict[str, Any]] = [
        {
            "asset_id": "kafka.orders_events",
            "layer": "kafka",
            "owner_team": "checkout-platform",
            "tier": "tier0",
            "dag_id": None,
            "spark_job": None,
            "sla_freshness_minutes": 5,
            "current_config_version": "schema-v2.1.0",
            "last_known_good_version": "schema-v2.0.3",
            "schema_version": 2,
            "status": "healthy",
            "freshness_lag_minutes": 0.4,
            "missing_partitions": [],
            "pipeline_paused": False,
            "retry_count": 0,
            "cost_multiplier": 1.0,
        },
        {
            "asset_id": "kafka.payments_events",
            "layer": "kafka",
            "owner_team": "payments-core",
            "tier": "tier0",
            "dag_id": None,
            "spark_job": None,
            "sla_freshness_minutes": 5,
            "current_config_version": "broker-4.3.2",
            "last_known_good_version": "broker-4.3.2",
            "schema_version": 2,
            "status": "healthy",
            "freshness_lag_minutes": 0.5,
            "missing_partitions": [],
            "pipeline_paused": False,
            "retry_count": 0,
            "cost_multiplier": 1.0,
        },
        {
            "asset_id": "kafka.clickstream_events",
            "layer": "kafka",
            "owner_team": "web-edge",
            "tier": "tier1",
            "dag_id": None,
            "spark_job": None,
            "sla_freshness_minutes": 10,
            "current_config_version": "edge-v3.4.0",
            "last_known_good_version": "edge-v3.3.9",
            "schema_version": 2,
            "status": "healthy",
            "freshness_lag_minutes": 0.8,
            "missing_partitions": [],
            "pipeline_paused": False,
            "retry_count": 0,
            "cost_multiplier": 1.0,
        },
        {
            "asset_id": "bronze.orders_raw",
            "layer": "bronze",
            "owner_team": "data-ingestion",
            "tier": "tier0",
            "dag_id": "dag_bronze_orders_ingest",
            "spark_job": "spark_bronze_orders",
            "sla_freshness_minutes": 10,
            "current_config_version": "v1.8.0",
            "last_known_good_version": "v1.7.9",
            "schema_version": 2,
            "status": "healthy",
            "freshness_lag_minutes": 2.1,
            "missing_partitions": [],
            "pipeline_paused": False,
            "retry_count": 0,
            "cost_multiplier": 1.0,
        },
        {
            "asset_id": "bronze.payments_raw",
            "layer": "bronze",
            "owner_team": "data-ingestion",
            "tier": "tier0",
            "dag_id": "dag_bronze_payments_ingest",
            "spark_job": "spark_bronze_payments",
            "sla_freshness_minutes": 10,
            "current_config_version": "v1.6.2",
            "last_known_good_version": "v1.6.1",
            "schema_version": 2,
            "status": "healthy",
            "freshness_lag_minutes": 2.4,
            "missing_partitions": [],
            "pipeline_paused": False,
            "retry_count": 0,
            "cost_multiplier": 1.0,
        },
        {
            "asset_id": "bronze.clickstream_raw",
            "layer": "bronze",
            "owner_team": "data-ingestion",
            "tier": "tier1",
            "dag_id": "dag_bronze_clickstream_ingest",
            "spark_job": "spark_bronze_clickstream",
            "sla_freshness_minutes": 15,
            "current_config_version": "v1.5.0",
            "last_known_good_version": "v1.4.9",
            "schema_version": 2,
            "status": "healthy",
            "freshness_lag_minutes": 3.0,
            "missing_partitions": [],
            "pipeline_paused": False,
            "retry_count": 0,
            "cost_multiplier": 1.0,
        },
        {
            "asset_id": "silver.orders_enriched",
            "layer": "silver",
            "owner_team": "commerce-analytics",
            "tier": "tier0",
            "dag_id": "dag_silver_orders_transform",
            "spark_job": "spark_silver_orders_transform",
            "sla_freshness_minutes": 15,
            "current_config_version": "v2.14.0",
            "last_known_good_version": "v2.13.4",
            "schema_version": 2,
            "status": "healthy",
            "freshness_lag_minutes": 4.2,
            "missing_partitions": [],
            "pipeline_paused": False,
            "retry_count": 0,
            "cost_multiplier": 1.0,
        },
        {
            "asset_id": "silver.user_sessions",
            "layer": "silver",
            "owner_team": "growth-engineering",
            "tier": "tier1",
            "dag_id": "dag_silver_sessions_transform",
            "spark_job": "spark_silver_sessions_transform",
            "sla_freshness_minutes": 20,
            "current_config_version": "v1.9.2",
            "last_known_good_version": "v1.9.1",
            "schema_version": 2,
            "status": "healthy",
            "freshness_lag_minutes": 5.5,
            "missing_partitions": [],
            "pipeline_paused": False,
            "retry_count": 0,
            "cost_multiplier": 1.0,
        },
        {
            "asset_id": "gold.daily_revenue_mv",
            "layer": "gold",
            "owner_team": "finance-bi",
            "tier": "tier0",
            "dag_id": "dag_gold_revenue_mv",
            "spark_job": "spark_gold_revenue_mv",
            "sla_freshness_minutes": 15,
            "current_config_version": "v3.2.0",
            "last_known_good_version": "v3.1.8",
            "schema_version": 2,
            "status": "healthy",
            "freshness_lag_minutes": 6.1,
            "missing_partitions": [],
            "pipeline_paused": False,
            "retry_count": 0,
            "cost_multiplier": 1.0,
        },
        {
            "asset_id": "gold.funnel_conversion_mv",
            "layer": "gold",
            "owner_team": "growth-engineering",
            "tier": "tier1",
            "dag_id": "dag_gold_funnel_mv",
            "spark_job": "spark_gold_funnel_mv",
            "sla_freshness_minutes": 30,
            "current_config_version": "v2.4.0",
            "last_known_good_version": "v2.3.7",
            "schema_version": 2,
            "status": "healthy",
            "freshness_lag_minutes": 8.0,
            "missing_partitions": [],
            "pipeline_paused": False,
            "retry_count": 0,
            "cost_multiplier": 1.0,
        },
        {
            "asset_id": "consumer.exec_finance_dashboard",
            "layer": "consumer",
            "owner_team": "finance-bi",
            "tier": "tier0",
            "dag_id": None,
            "spark_job": None,
            "sla_freshness_minutes": 20,
            "current_config_version": "dash-v4.1",
            "last_known_good_version": "dash-v4.0",
            "schema_version": 2,
            "status": "healthy",
            "freshness_lag_minutes": 6.5,
            "missing_partitions": [],
            "pipeline_paused": False,
            "retry_count": 0,
            "cost_multiplier": 1.0,
        },
        {
            "asset_id": "consumer.realtime_fraud_scorer",
            "layer": "consumer",
            "owner_team": "risk-ml",
            "tier": "tier0",
            "dag_id": None,
            "spark_job": None,
            "sla_freshness_minutes": 15,
            "current_config_version": "scorer-v5.0",
            "last_known_good_version": "scorer-v4.9",
            "schema_version": 2,
            "status": "healthy",
            "freshness_lag_minutes": 4.8,
            "missing_partitions": [],
            "pipeline_paused": False,
            "retry_count": 0,
            "cost_multiplier": 1.0,
        },
        {
            "asset_id": "consumer.growth_attribution_api",
            "layer": "consumer",
            "owner_team": "growth-engineering",
            "tier": "tier1",
            "dag_id": None,
            "spark_job": None,
            "sla_freshness_minutes": 35,
            "current_config_version": "api-v2.2",
            "last_known_good_version": "api-v2.1",
            "schema_version": 2,
            "status": "healthy",
            "freshness_lag_minutes": 8.5,
            "missing_partitions": [],
            "pipeline_paused": False,
            "retry_count": 0,
            "cost_multiplier": 1.0,
        },
    ]
    return {a["asset_id"]: a for a in assets}


def load_openlineage_edges(lineage_path: Path | None = None) -> list[LineageEdgeModel]:
    """Parse explicit OpenLineage events into directed upstream -> downstream asset edges."""
    path = lineage_path or LINEAGE_FILE
    raw = json.loads(path.read_text(encoding="utf-8"))
    edges: list[LineageEdgeModel] = []
    # Explicit consumer mapping for the multi-input serving job to avoid synthetic cross-edges.
    explicit_serving_pairs = {
        ("gold.daily_revenue_mv", "consumer.exec_finance_dashboard"),
        ("silver.orders_enriched", "consumer.realtime_fraud_scorer"),
        ("gold.funnel_conversion_mv", "consumer.growth_attribution_api"),
    }
    for evt in raw.get("events", []):
        job_name = evt["job"]["name"]
        run_id = evt["run"]["runId"]
        inputs = [i["name"] for i in evt.get("inputs", [])]
        outputs = [o["name"] for o in evt.get("outputs", [])]
        for src in inputs:
            for dst in outputs:
                if job_name == "serving_sla_consumers" and (src, dst) not in explicit_serving_pairs:
                    continue
                edge_id = f"edge:{src}->{dst}"
                edges.append(
                    LineageEdgeModel(
                        edge_id=edge_id,
                        source_asset_id=src,
                        target_asset_id=dst,
                        job_name=job_name,
                        run_id=run_id,
                    )
                )
    return edges


class PlatformLineageGraph:
    """Directed lineage DAG supporting upstream root-cause traversal and subgraph extraction."""

    def __init__(self, edges: list[LineageEdgeModel] | None = None) -> None:
        self.edges: list[LineageEdgeModel] = edges if edges is not None else load_openlineage_edges()
        self.downstream: dict[str, list[str]] = defaultdict(list)
        self.upstream: dict[str, list[str]] = defaultdict(list)
        self.edge_by_pair: dict[tuple[str, str], LineageEdgeModel] = {}
        for edge in self.edges:
            self.downstream[edge.source_asset_id].append(edge.target_asset_id)
            self.upstream[edge.target_asset_id].append(edge.source_asset_id)
            self.edge_by_pair[(edge.source_asset_id, edge.target_asset_id)] = edge

    def ancestors(self, asset_id: str) -> set[str]:
        visited: set[str] = set()
        queue = deque(self.upstream.get(asset_id, []))
        while queue:
            curr = queue.popleft()
            if curr not in visited:
                visited.add(curr)
                queue.extend(self.upstream.get(curr, []))
        return visited

    def descendants(self, asset_id: str) -> set[str]:
        visited: set[str] = set()
        queue = deque(self.downstream.get(asset_id, []))
        while queue:
            curr = queue.popleft()
            if curr not in visited:
                visited.add(curr)
                queue.extend(self.downstream.get(curr, []))
        return visited

    def distance(self, src: str, dst: str) -> int | None:
        if src == dst:
            return 0
        visited = {src}
        queue: deque[tuple[str, int]] = deque([(src, 0)])
        while queue:
            node, dist = queue.popleft()
            for nxt in self.downstream.get(node, []):
                if nxt == dst:
                    return dist + 1
                if nxt not in visited:
                    visited.add(nxt)
                    queue.append((nxt, dist + 1))
        return None

    def subgraph_edges(self, asset_ids: set[str]) -> list[LineageEdgeModel]:
        return [
            e
            for e in self.edges
            if e.source_asset_id in asset_ids and e.target_asset_id in asset_ids
        ]

    def connected_components(self, asset_ids: set[str]) -> list[set[str]]:
        """Group affected assets that are causally connected via directed lineage paths."""
        undirected: dict[str, set[str]] = {a: set() for a in asset_ids}
        for a in asset_ids:
            desc = self.descendants(a)
            for b in asset_ids:
                if a != b and b in desc:
                    undirected[a].add(b)
                    undirected[b].add(a)
        visited: set[str] = set()
        components: list[set[str]] = []
        for node in sorted(asset_ids):
            if node in visited:
                continue
            comp: set[str] = set()
            q = deque([node])
            visited.add(node)
            while q:
                curr = q.popleft()
                comp.add(curr)
                for nbr in undirected[curr]:
                    if nbr not in visited:
                        visited.add(nbr)
                        q.append(nbr)
            components.append(comp)
        return components


class PlatformStateStore:
    """Durable operational state of the fixture data platform for real remediation & rollback."""

    def __init__(self, state_path: Path) -> None:
        self.state_path = state_path
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        if self.state_path.exists():
            self._assets: dict[str, dict[str, Any]] = json.loads(
                self.state_path.read_text(encoding="utf-8")
            )
        else:
            self._assets = default_platform_assets()
            self.save()

    def reset(self) -> None:
        self._assets = default_platform_assets()
        self.save()

    def save(self) -> None:
        self.state_path.write_text(json.dumps(self._assets, indent=2), encoding="utf-8")

    def get(self, asset_id: str) -> dict[str, Any]:
        if asset_id not in self._assets:
            raise KeyError(f"Unknown platform asset: {asset_id}")
        return copy.deepcopy(self._assets[asset_id])

    def list_assets(self) -> list[AssetNodeModel]:
        ordered = sorted(
            self._assets.values(),
            key=lambda a: (LAYER_ORDER.get(a["layer"], 99), a["asset_id"]),
        )
        return [AssetNodeModel(**{k: a[k] for k in AssetNodeModel.model_fields}) for a in ordered]

    def update(self, asset_id: str, patch: dict[str, Any]) -> dict[str, Any]:
        if asset_id not in self._assets:
            raise KeyError(f"Unknown platform asset: {asset_id}")
        self._assets[asset_id].update(patch)
        self.save()
        return copy.deepcopy(self._assets[asset_id])

    def apply_signal_effects(self, signals: list[dict[str, Any]]) -> None:
        """Reflect real failure symptoms on fixture assets so preconditions & post-checks verify true state."""
        for sig in signals:
            if sig.get("is_retraction"):
                continue
            aid = sig.get("asset_id")
            if aid not in self._assets:
                continue
            asset = self._assets[aid]
            sev = sig.get("severity", "INFO")
            stype = sig.get("signal_type", "")
            metric = sig.get("metric_name") or ""
            mval = sig.get("metric_value")
            if sev in {"ERROR", "CRITICAL"}:
                asset["status"] = "failing"
            elif sev == "WARNING" and asset["status"] == "healthy" and stype != "METRIC_ANOMALY":
                asset["status"] = "degraded"
            if metric == "freshness_lag_minutes" and isinstance(mval, (int, float)):
                asset["freshness_lag_minutes"] = max(float(asset["freshness_lag_minutes"]), float(mval))
            if metric == "cost_multiplier" and isinstance(mval, (int, float)):
                asset["cost_multiplier"] = max(float(asset["cost_multiplier"]), float(mval))
            if metric == "task_retry_count" and isinstance(mval, (int, float)):
                asset["retry_count"] = max(int(asset["retry_count"]), int(mval))
            if stype == "DQ_FAILURE" and sig.get("partition_key"):
                part = str(sig["partition_key"])
                if part not in asset["missing_partitions"]:
                    asset["missing_partitions"].append(part)
            if stype == "DEPLOYMENT_EVENT" and sig.get("commit_version"):
                asset["current_config_version"] = str(sig["commit_version"])
        self.save()
