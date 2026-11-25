"""Apache Iceberg V2 Incident Evidence Lakehouse with Snapshots, Time Travel, Compaction, and DuckDB SQL."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import duckdb
import pyarrow as pa
from pyiceberg.catalog.sql import SqlCatalog
from pyiceberg.exceptions import NamespaceAlreadyExistsError, NoSuchTableError
from pyiceberg.table import Table

TABLE_SCHEMAS: dict[str, pa.Schema] = {
    "bronze.telemetry_signals": pa.schema(
        [
            ("signal_id", pa.string()),
            ("signal_type", pa.string()),
            ("asset_id", pa.string()),
            ("severity", pa.string()),
            ("event_time_ms", pa.int64()),
            ("processing_time_ms", pa.int64()),
            ("trace_id", pa.string()),
            ("span_id", pa.string()),
            ("run_id", pa.string()),
            ("scenario_tag", pa.string()),
            ("metric_name", pa.string()),
            ("metric_value", pa.float64()),
            ("message", pa.string()),
            ("commit_version", pa.string()),
            ("partition_key", pa.string()),
            ("schema_version", pa.int32()),
            ("cost_usd_delta", pa.float64()),
            ("is_retraction", pa.bool_()),
            ("lineage_job_name", pa.string()),
            ("producer_service", pa.string()),
            ("stream_offset", pa.int64()),
        ]
    ),
    "bronze.quarantine_dlq": pa.schema(
        [
            ("dlq_id", pa.string()),
            ("offset", pa.int64()),
            ("reason", pa.string()),
            ("raw_payload", pa.string()),
            ("quarantined_at", pa.string()),
        ]
    ),
    "silver.asset_lineage_graph": pa.schema(
        [
            ("edge_id", pa.string()),
            ("source_asset_id", pa.string()),
            ("target_asset_id", pa.string()),
            ("job_name", pa.string()),
            ("run_id", pa.string()),
        ]
    ),
    "silver.correlated_incidents": pa.schema(
        [
            ("incident_id", pa.string()),
            ("title", pa.string()),
            ("scenario_type", pa.string()),
            ("root_asset_id", pa.string()),
            ("impacted_assets_json", pa.string()),
            ("raw_alert_count", pa.int32()),
            ("severity", pa.string()),
            ("status", pa.string()),
            ("is_false_positive", pa.bool_()),
            ("first_event_time_ms", pa.int64()),
            ("detected_at_ms", pa.int64()),
            ("signal_ids_json", pa.string()),
            ("span_ids_json", pa.string()),
            ("lineage_edges_json", pa.string()),
            ("commit_versions_json", pa.string()),
            ("storm_compression_ratio", pa.float64()),
            ("recommended_tool", pa.string()),
            ("recommended_parameters_json", pa.string()),
        ]
    ),
    "gold.rca_hypotheses": pa.schema(
        [
            ("hypothesis_id", pa.string()),
            ("incident_id", pa.string()),
            ("rank", pa.int32()),
            ("root_asset_id", pa.string()),
            ("root_cause_category", pa.string()),
            ("confidence", pa.float64()),
            ("rationale", pa.string()),
            ("recommended_tool", pa.string()),
            ("recommended_parameters_json", pa.string()),
            ("evidence_pointers_json", pa.string()),
            ("verified_citation_count", pa.int32()),
            ("total_citation_count", pa.int32()),
            ("hallucinated_citation_count", pa.int32()),
        ]
    ),
    "gold.remediation_plans": pa.schema(
        [
            ("plan_id", pa.string()),
            ("incident_id", pa.string()),
            ("tool_name", pa.string()),
            ("target_asset_id", pa.string()),
            ("parameters_json", pa.string()),
            ("idempotency_key", pa.string()),
            ("status", pa.string()),
            ("dry_run_preview", pa.string()),
            ("preconditions_passed", pa.bool_()),
            ("precondition_details_json", pa.string()),
            ("policy_decision_json", pa.string()),
            ("proposed_by", pa.string()),
            ("approved_by", pa.string()),
            ("approved_at", pa.string()),
            ("executed_at", pa.string()),
            ("execution_count", pa.int32()),
            ("post_check_passed", pa.bool_()),
            ("post_check_details", pa.string()),
            ("rollback_performed", pa.bool_()),
            ("pre_action_snapshot_json", pa.string()),
            ("post_action_snapshot_json", pa.string()),
        ]
    ),
    "gold.remediation_audit_log": pa.schema(
        [
            ("audit_id", pa.string()),
            ("seq_no", pa.int64()),
            ("timestamp", pa.string()),
            ("event_type", pa.string()),
            ("plan_id", pa.string()),
            ("incident_id", pa.string()),
            ("actor_id", pa.string()),
            ("actor_role", pa.string()),
            ("tool_name", pa.string()),
            ("target_asset_id", pa.string()),
            ("outcome", pa.string()),
            ("details_json", pa.string()),
            ("prev_hash", pa.string()),
            ("entry_hash", pa.string()),
        ]
    ),
    "quality.dq_results": pa.schema(
        [
            ("check_id", pa.string()),
            ("run_id", pa.string()),
            ("table_name", pa.string()),
            ("check_name", pa.string()),
            ("passed", pa.bool_()),
            ("metric_value", pa.float64()),
            ("threshold", pa.string()),
            ("details", pa.string()),
            ("evaluated_at", pa.string()),
        ]
    ),
}

NAMESPACES = ("bronze", "silver", "gold", "quality")


class IcebergEvidenceLakehouse:
    """Manages the 8 Apache Iceberg V2 tables for incident evidence, RCA, remediations, and audit."""

    def __init__(self, warehouse_dir: Path, catalog_db: Path) -> None:
        self.warehouse_dir = warehouse_dir.resolve()
        self.catalog_db = catalog_db.resolve()
        self.warehouse_dir.mkdir(parents=True, exist_ok=True)
        self.catalog_db.parent.mkdir(parents=True, exist_ok=True)
        self.catalog = SqlCatalog(
            "agentic_sre_local",
            **{
                "uri": f"sqlite:///{self.catalog_db}",
                "warehouse": f"file://{self.warehouse_dir}",
            },
        )
        self._ensure_tables()

    def _ensure_tables(self) -> None:
        for ns in NAMESPACES:
            try:
                self.catalog.create_namespace(ns)
            except NamespaceAlreadyExistsError:
                pass
        for table_name, arrow_schema in TABLE_SCHEMAS.items():
            try:
                self.catalog.load_table(table_name)
            except NoSuchTableError:
                self.catalog.create_table(
                    identifier=table_name,
                    schema=arrow_schema,
                    properties={
                        "format-version": "2",
                        "write.parquet.compression-codec": "zstd",
                    },
                )

    def load_table(self, table_name: str) -> Table:
        return self.catalog.load_table(table_name)

    def _rows_to_arrow(self, table_name: str, rows: list[dict[str, Any]]) -> pa.Table:
        schema = TABLE_SCHEMAS[table_name]
        if not rows:
            return pa.Table.from_pylist([], schema=schema)
        normalized: list[dict[str, Any]] = []
        for row in rows:
            item: dict[str, Any] = {}
            for field in schema:
                val = row.get(field.name)
                if val is not None and pa.types.is_string(field.type) and not isinstance(val, str):
                    val = json.dumps(val)
                item[field.name] = val
            normalized.append(item)
        return pa.Table.from_pylist(normalized, schema=schema)

    def overwrite(self, table_name: str, rows: list[dict[str, Any]]) -> int:
        tbl = self.load_table(table_name)
        arrow_tbl = self._rows_to_arrow(table_name, rows)
        tbl.overwrite(arrow_tbl)
        return len(rows)

    def append(self, table_name: str, rows: list[dict[str, Any]]) -> int:
        if not rows:
            return 0
        tbl = self.load_table(table_name)
        arrow_tbl = self._rows_to_arrow(table_name, rows)
        tbl.append(arrow_tbl)
        return len(rows)

    def read_arrow(self, table_name: str, snapshot_id: int | None = None) -> pa.Table:
        tbl = self.load_table(table_name)
        if tbl.current_snapshot() is None:
            return pa.Table.from_pylist([], schema=TABLE_SCHEMAS[table_name])
        scan = tbl.scan(snapshot_id=snapshot_id) if snapshot_id is not None else tbl.scan()
        return scan.to_arrow()

    def read_rows(self, table_name: str, snapshot_id: int | None = None) -> list[dict[str, Any]]:
        return self.read_arrow(table_name, snapshot_id=snapshot_id).to_pylist()

    def snapshot_history(self, table_name: str) -> list[dict[str, Any]]:
        tbl = self.load_table(table_name)
        history: list[dict[str, Any]] = []
        for snap in tbl.metadata.snapshots:
            summary_props = dict(snap.summary.additional_properties) if snap.summary else {}
            history.append(
                {
                    "snapshot_id": snap.snapshot_id,
                    "parent_snapshot_id": snap.parent_snapshot_id,
                    "timestamp_ms": snap.timestamp_ms,
                    "operation": str(snap.summary.operation.value) if snap.summary else "unknown",
                    "total_records": summary_props.get("total-records"),
                    "total_data_files": summary_props.get("total-data-files"),
                }
            )
        return history

    def count_data_files(self, table_name: str) -> int:
        tbl = self.load_table(table_name)
        if tbl.current_snapshot() is None:
            return 0
        files_arrow = tbl.inspect.files()
        return int(files_arrow.num_rows)

    def compact_table(self, table_name: str) -> dict[str, Any]:
        """Rewrite fragmented Iceberg V2 data files into a single compacted Parquet file and measure latency."""
        files_before = self.count_data_files(table_name)
        t0 = time.perf_counter()
        arrow_tbl = self.read_arrow(table_name)
        read_before_ms = round((time.perf_counter() - t0) * 1000.0, 3)

        row_count = arrow_tbl.num_rows
        if row_count > 0:
            self.load_table(table_name).overwrite(arrow_tbl)

        files_after = self.count_data_files(table_name)
        t1 = time.perf_counter()
        _ = self.read_arrow(table_name)
        read_after_ms = round((time.perf_counter() - t1) * 1000.0, 3)

        return {
            "table_name": table_name,
            "row_count": row_count,
            "data_files_before": files_before,
            "data_files_after": files_after,
            "read_ms_before": read_before_ms,
            "read_ms_after": read_after_ms,
        }

    def table_stats(self) -> dict[str, dict[str, Any]]:
        stats: dict[str, dict[str, Any]] = {}
        for name in TABLE_SCHEMAS:
            tbl = self.load_table(name)
            snap = tbl.current_snapshot()
            rows = self.read_arrow(name).num_rows if snap else 0
            stats[name] = {
                "rows": int(rows),
                "data_files": self.count_data_files(name),
                "snapshots": len(tbl.metadata.snapshots),
                "current_snapshot_id": snap.snapshot_id if snap else None,
                "format_version": tbl.metadata.format_version,
            }
        return stats

    def duckdb_analytics_summary(self) -> dict[str, Any]:
        """Run analytical DuckDB SQL queries directly over Iceberg V2 Arrow snapshots."""
        con = duckdb.connect(database=":memory:")
        try:
            for tbl_name in TABLE_SCHEMAS:
                safe_name = tbl_name.replace(".", "_")
                con.register(safe_name, self.read_arrow(tbl_name))

            incident_row = con.execute(
                """
                SELECT
                    COUNT(*) AS total_incidents,
                    SUM(CASE WHEN is_false_positive THEN 1 ELSE 0 END) AS false_positives_suppressed,
                    SUM(CASE WHEN NOT is_false_positive THEN 1 ELSE 0 END) AS actionable_incidents,
                    COALESCE(SUM(raw_alert_count), 0) AS total_raw_alerts,
                    ROUND(AVG(storm_compression_ratio), 2) AS avg_storm_compression_ratio
                FROM silver_correlated_incidents
                """
            ).fetchone()

            rca_row = con.execute(
                """
                SELECT
                    COUNT(*) AS total_hypotheses,
                    COALESCE(SUM(verified_citation_count), 0) AS verified_citations,
                    COALESCE(SUM(total_citation_count), 0) AS total_citations,
                    COALESCE(SUM(hallucinated_citation_count), 0) AS hallucinated_citations
                FROM gold_rca_hypotheses
                """
            ).fetchone()

            dq_row = con.execute(
                """
                SELECT
                    COUNT(*) AS total_checks,
                    SUM(CASE WHEN passed THEN 1 ELSE 0 END) AS passed_checks
                FROM quality_dq_results
                """
            ).fetchone()

            plan_row = con.execute(
                """
                SELECT
                    COUNT(*) AS total_plans,
                    SUM(CASE WHEN status = 'COMPLETED' THEN 1 ELSE 0 END) AS completed_plans,
                    SUM(CASE WHEN rollback_performed THEN 1 ELSE 0 END) AS rolled_back_plans
                FROM gold_remediation_plans
                """
            ).fetchone()

            audit_count = con.execute("SELECT COUNT(*) FROM gold_remediation_audit_log").fetchone()
            dlq_count = con.execute("SELECT COUNT(*) FROM bronze_quarantine_dlq").fetchone()
            sig_count = con.execute("SELECT COUNT(*) FROM bronze_telemetry_signals").fetchone()

            verified = int(rca_row[1] or 0) if rca_row else 0
            total_cit = int(rca_row[2] or 0) if rca_row else 0
            halluc = int(rca_row[3] or 0) if rca_row else 0
            halluc_rate = round((halluc / total_cit) * 100.0, 4) if total_cit > 0 else 0.0

            return {
                "signals_ingested": int(sig_count[0] or 0) if sig_count else 0,
                "dlq_quarantined": int(dlq_count[0] or 0) if dlq_count else 0,
                "total_incidents": int(incident_row[0] or 0) if incident_row else 0,
                "false_positives_suppressed": int(incident_row[1] or 0) if incident_row else 0,
                "actionable_incidents": int(incident_row[2] or 0) if incident_row else 0,
                "total_raw_alerts": int(incident_row[3] or 0) if incident_row else 0,
                "avg_storm_compression_ratio": float(incident_row[4] or 1.0) if incident_row else 1.0,
                "total_hypotheses": int(rca_row[0] or 0) if rca_row else 0,
                "verified_citations": verified,
                "total_citations": total_cit,
                "hallucinated_citations": halluc,
                "hallucinated_evidence_rate_pct": halluc_rate,
                "dq_total_checks": int(dq_row[0] or 0) if dq_row else 0,
                "dq_passed_checks": int(dq_row[1] or 0) if dq_row else 0,
                "remediation_plans_total": int(plan_row[0] or 0) if plan_row else 0,
                "remediation_plans_completed": int(plan_row[1] or 0) if plan_row else 0,
                "remediation_plans_rolled_back": int(plan_row[2] or 0) if plan_row else 0,
                "audit_log_entries": int(audit_count[0] or 0) if audit_count else 0,
            }
        finally:
            con.close()
