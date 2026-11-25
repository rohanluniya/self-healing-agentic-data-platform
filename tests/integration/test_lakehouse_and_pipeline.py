"""Integration tests for Apache Iceberg V2 lakehouse, snapshots, time travel, compaction, and DuckDB analytics."""

from __future__ import annotations

from agentic_sre.config import Settings
from agentic_sre.lakehouse import IcebergEvidenceLakehouse
from services.pipeline.run_pipeline import run_end_to_end_pipeline


def test_end_to_end_pipeline_populates_all_eight_iceberg_v2_tables_and_passes_dq(
    isolated_settings: Settings,
) -> None:
    res = run_end_to_end_pipeline(
        profile="local",
        seed=42,
        compact=True,
        settings=isolated_settings,
    )
    assert res["dq_all_passed"] is True
    assert res["analytics"]["dq_passed_checks"] == 7
    assert res["analytics"]["hallucinated_evidence_rate_pct"] == 0.0
    assert res["analytics"]["false_positives_suppressed"] == 1
    assert res["analytics"]["actionable_incidents"] == 8
    assert res["analytics"]["dlq_quarantined"] == 2
    assert len(res["iceberg_tables"]) == 8

    for tbl_name, stats in res["iceberg_tables"].items():
        assert stats["format_version"] == 2, f"{tbl_name} must be Iceberg V2"
        assert stats["rows"] > 0, f"{tbl_name} should be populated"


def test_iceberg_time_travel_and_compaction_preserve_row_counts(isolated_settings: Settings) -> None:
    lh = IcebergEvidenceLakehouse(isolated_settings.warehouse_dir, isolated_settings.catalog_db)

    # Append 6 small single-row batches to create deliberate small-file fragmentation
    for i in range(6):
        lh.append(
            "bronze.quarantine_dlq",
            [
                {
                    "dlq_id": f"dlq-frag-{i}",
                    "offset": i,
                    "reason": "fragmented_write_test",
                    "raw_payload": f"{{\"idx\":{i}}}",
                    "quarantined_at": "2026-11-24T12:00:00Z",
                }
            ],
        )

    history = lh.snapshot_history("bronze.quarantine_dlq")
    assert len(history) == 6
    first_snap_id = history[0]["snapshot_id"]
    rows_at_snap_1 = lh.read_rows("bronze.quarantine_dlq", snapshot_id=first_snap_id)
    assert len(rows_at_snap_1) == 1

    assert lh.count_data_files("bronze.quarantine_dlq") == 6
    compact_res = lh.compact_table("bronze.quarantine_dlq")
    assert compact_res["data_files_before"] == 6
    assert compact_res["data_files_after"] == 1
    assert compact_res["row_count"] == 6
    assert len(lh.read_rows("bronze.quarantine_dlq")) == 6
