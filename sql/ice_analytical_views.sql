-- DuckDB / Iceberg V2 Analytical Views over the Incident Evidence Lakehouse

-- 1. Incident Storm Compression & False-Positive Suppression Summary
SELECT
    scenario_type,
    COUNT(*) AS correlated_incidents,
    SUM(CASE WHEN is_false_positive THEN 1 ELSE 0 END) AS suppressed_false_positives,
    SUM(raw_alert_count) AS total_raw_alerts,
    ROUND(AVG(storm_compression_ratio), 2) AS avg_compression_ratio
FROM silver_correlated_incidents
GROUP BY scenario_type
ORDER BY total_raw_alerts DESC;

-- 2. Zero-Hallucination Citation Grounding Verification
SELECT
    incident_id,
    root_asset_id,
    root_cause_category,
    rank,
    confidence,
    verified_citation_count,
    total_citation_count,
    hallucinated_citation_count,
    CASE
        WHEN total_citation_count = 0 THEN 0.0
        ELSE ROUND(100.0 * hallucinated_citation_count / total_citation_count, 4)
    END AS hallucinated_rate_pct
FROM gold_rca_hypotheses
ORDER BY incident_id, rank;

-- 3. Quarantine DLQ Audit Summary
SELECT
    SUBSTR(reason, 1, 80) AS failure_reason,
    COUNT(*) AS quarantined_records,
    MIN(quarantined_at) AS first_seen_utc,
    MAX(quarantined_at) AS last_seen_utc
FROM bronze_quarantine_dlq
GROUP BY 1
ORDER BY quarantined_records DESC;
