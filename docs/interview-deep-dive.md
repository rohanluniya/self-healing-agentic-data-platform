# Technical Interview Deep Dive

## 1. Why Deterministic Correlation & RCA Before Any LLM?
- **Determinism & Latency:** Graph ancestry, deployment-precedence checks, and schema-diff correlation run in `0.111 ms` p50 (`0.146 ms` p95) and produce identical results for identical inputs.
- **Zero Hallucination Guarantee:** Every evidence pointer (`signal_id`, `span_id`, `commit_version`, `lineage_edge`) is cross-checked against persisted Iceberg V2 rows before reaching an operator or remediation planner (`0.0%` hallucinated evidence rate).
- **Least Privilege for Optional LLMs:** Even when `OptionalLocalLLMAdapter` is enabled, it only summarizes an already-verified evidence bundle and has zero access to tool execution APIs.

## 2. How Does the Platform Prevent Agentic Blast Radius?
Five independent layers of defense-in-depth:
1. **Default Read-Only Mode (`SRE_AGENT_MODE=read_only`):** Execution is hard-blocked unless explicitly escalated to `guarded_active`.
2. **Typed Tool Allowlist (5 tools only):** Arbitrary SQL, shell commands, `drop_table`, and `delete_prod_data` are hard-denied in OPA Rego v1 (`risk_level="forbidden"`).
3. **Bounded Parameters:** `max_retries` is capped at `1..3`, `partition_count` at `1..24`, `timeout_seconds` at `<= 900`, and `rollback_config_version` must match `last_known_good_version`.
4. **RBAC Separation of Duties:** `viewer` can only read, `operator` can dry-run/execute/rollback, and `approver` can approve; OPA enforces `operator_id != approver_id`.
5. **Idempotency & Auto-Rollback:** Duplicate `idempotency_key` calls return cached receipts without re-mutating state (`execution_count == 1`), and failed post-action health checks automatically restore `pre_action_snapshot`.

## 3. How Are Event Time vs. Processing Time Handled for Late Data?
- Late-arriving clickstream records carry `event_time_ms` 4 hours behind `processing_time_ms`.
- Alert correlation groups on `processing_time_ms` so the late-arrival DQ alert on `bronze.clickstream_raw` clusters with the immediately triggered reconciliation drift alerts on `silver.user_sessions` and `gold.funnel_conversion_mv`.
- Causal classification inspects `processing_time_ms - event_time_ms` lag (`>= 1800s`) and maps the root cause to `late_arriving_data`, proposing a bounded, idempotent `backfill_partition` on `silver.user_sessions`.

## 4. How Does Crash Recovery Work If the Control Plane Loses Local Disk State?
- Operational state (`.local_data/state/platform_state.json`) is treated as a disposable cache.
- All authoritative telemetry signals, correlated incidents, remediation plans, and audit entries live in Apache Iceberg V2 snapshots.
- Chaos Drill 6 deletes `platform_state.json` completely and executes `rebuild_platform_state_from_iceberg()`, proving deterministic reconstruction of all 13 assets and applied remediation snapshots.

## 5. How Do You Prove Audit Log Immutability?
- Every `gold.remediation_audit_log` row includes a monotonic `seq_no`, `prev_hash`, and `entry_hash = SHA256(audit_id|seq_no|timestamp|event_type|plan_id|incident_id|actor_id|outcome|details_json|prev_hash)`.
- Chaos Drill 8 modifies a single field in a copy of the audit log and verifies `verify_audit_hash_chain()` immediately flags the exact tampered index and `audit_id`.
