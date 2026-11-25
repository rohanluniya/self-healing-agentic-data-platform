-- SLO Compliance, Remediation Outcomes, and Immutable Audit Queries

-- 1. Remediation Lifecycle Outcome Breakdown
SELECT
    tool_name,
    status,
    COUNT(*) AS plan_count,
    SUM(execution_count) AS total_executions,
    SUM(CASE WHEN rollback_performed THEN 1 ELSE 0 END) AS rollbacks_performed
FROM gold_remediation_plans
GROUP BY tool_name, status
ORDER BY plan_count DESC;

-- 2. Data Quality Pass Rate per Iceberg Table
SELECT
    table_name,
    COUNT(*) AS total_checks,
    SUM(CASE WHEN passed THEN 1 ELSE 0 END) AS passed_checks,
    ROUND(100.0 * SUM(CASE WHEN passed THEN 1 ELSE 0 END) / COUNT(*), 2) AS pass_rate_pct
FROM quality_dq_results
GROUP BY table_name
ORDER BY table_name;

-- 3. Immutable Audit Trail Ordered by Sequence Number
SELECT
    seq_no,
    timestamp,
    event_type,
    actor_id,
    actor_role,
    tool_name,
    target_asset_id,
    outcome,
    SUBSTR(entry_hash, 1, 16) AS hash_prefix
FROM gold_remediation_audit_log
ORDER BY seq_no ASC;
