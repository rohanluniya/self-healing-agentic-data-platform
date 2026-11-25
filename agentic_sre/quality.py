"""Data Quality checks over the Incident Evidence Lakehouse and Immutable Audit Chain."""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from typing import Any

from agentic_sre.lakehouse import IcebergEvidenceLakehouse


def verify_audit_hash_chain(audit_rows: list[dict[str, Any]]) -> tuple[bool, str]:
    """Verify every SHA-256 hash-chain link in gold.remediation_audit_log in strict sequence order."""
    ordered = sorted(audit_rows, key=lambda r: int(r.get("seq_no") or 0))
    expected_prev = "GENESIS_0000000000000000"
    for idx, row in enumerate(ordered):
        if row["prev_hash"] != expected_prev:
            return False, f"Broken prev_hash at index {idx} (audit_id={row['audit_id']})"
        canonical = (
            f"{row['audit_id']}|{int(row.get('seq_no') or 0)}|{row['timestamp']}|{row['event_type']}|{row['plan_id']}|"
            f"{row['incident_id']}|{row['actor_id']}|{row['outcome']}|{row['details_json']}|{row['prev_hash']}"
        )
        computed = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if computed != row["entry_hash"]:
            return False, f"Tampered entry_hash at index {idx} (audit_id={row['audit_id']})"
        expected_prev = str(row["entry_hash"])
    return True, f"Verified {len(ordered)} hash-chained audit entries"


def run_data_quality_suite(
    lakehouse: IcebergEvidenceLakehouse,
    run_id: str,
    known_assets: set[str],
) -> list[dict[str, Any]]:
    """Run all 7 governance & data-quality checks and persist results to quality.dq_results."""
    now = datetime.now(UTC).isoformat()
    signals = lakehouse.read_rows("bronze.telemetry_signals")
    dlq = lakehouse.read_rows("bronze.quarantine_dlq")
    incidents = lakehouse.read_rows("silver.correlated_incidents")
    hypotheses = lakehouse.read_rows("gold.rca_hypotheses")
    plans = lakehouse.read_rows("gold.remediation_plans")
    audit = lakehouse.read_rows("gold.remediation_audit_log")

    checks: list[dict[str, Any]] = []

    def _add(table: str, name: str, passed: bool, val: float, threshold: str, details: str) -> None:
        checks.append(
            {
                "check_id": f"dq-{uuid.uuid4().hex[:10]}",
                "run_id": run_id,
                "table_name": table,
                "check_name": name,
                "passed": passed,
                "metric_value": float(val),
                "threshold": threshold,
                "details": details,
                "evaluated_at": now,
            }
        )

    # 1. Non-empty bronze telemetry ingestion
    _add(
        "bronze.telemetry_signals",
        "bronze_telemetry_non_empty",
        len(signals) > 0,
        float(len(signals)),
        "> 0",
        f"Persisted {len(signals)} validated Avro telemetry signals",
    )

    # 2. Event-time & processing-time validity contract
    invalid_ts = sum(
        1 for s in signals if int(s["event_time_ms"]) <= 0 or int(s["processing_time_ms"]) <= 0
    )
    _add(
        "bronze.telemetry_signals",
        "event_time_contract_valid",
        invalid_ts == 0,
        float(invalid_ts),
        "== 0",
        f"{invalid_ts} records with non-positive event/processing timestamps",
    )

    # 3. Quarantine DLQ isolation (zero malformed signal_ids leaked into bronze)
    leaked_malformed = sum(1 for s in signals if "malformed" in str(s.get("signal_id", "")))
    _add(
        "bronze.quarantine_dlq",
        "dlq_quarantine_isolation",
        leaked_malformed == 0,
        float(len(dlq)),
        "leaked == 0",
        f"Quarantined {len(dlq)} malformed records; {leaked_malformed} leaked into bronze",
    )

    # 4. Lineage referential integrity for correlated incidents
    unknown_roots = [i["root_asset_id"] for i in incidents if i["root_asset_id"] not in known_assets]
    _add(
        "silver.correlated_incidents",
        "lineage_asset_referential_integrity",
        len(unknown_roots) == 0,
        float(len(unknown_roots)),
        "== 0",
        f"{len(incidents)} correlated incidents checked; {len(unknown_roots)} unknown assets",
    )

    # 5. Zero-hallucination citation grounding across all RCA hypotheses
    total_halluc = sum(int(h.get("hallucinated_citation_count") or 0) for h in hypotheses)
    total_ver = sum(int(h.get("verified_citation_count") or 0) for h in hypotheses)
    _add(
        "gold.rca_hypotheses",
        "rca_zero_hallucinated_citations",
        total_halluc == 0 and total_ver > 0,
        float(total_halluc),
        "== 0",
        f"{total_ver} verified citations, {total_halluc} hallucinated citations across {len(hypotheses)} hypotheses",
    )

    # 6. False-positive non-mutation invariant
    fp_ids = {i["incident_id"] for i in incidents if bool(i.get("is_false_positive"))}
    mutated_fps = [
        p["plan_id"]
        for p in plans
        if p["incident_id"] in fp_ids and p["status"] in {"APPROVED", "COMPLETED"}
    ]
    _add(
        "gold.remediation_plans",
        "false_positive_zero_mutation",
        len(mutated_fps) == 0,
        float(len(mutated_fps)),
        "== 0",
        f"{len(fp_ids)} false-positive incidents tracked; {len(mutated_fps)} mutated",
    )

    # 7. Immutable SHA-256 audit log hash-chain integrity
    chain_ok, chain_msg = verify_audit_hash_chain(audit)
    _add(
        "gold.remediation_audit_log",
        "audit_log_hash_chain_integrity",
        chain_ok,
        float(len(audit)),
        "valid_chain == true",
        chain_msg,
    )

    lakehouse.overwrite("quality.dq_results", checks)
    return checks
