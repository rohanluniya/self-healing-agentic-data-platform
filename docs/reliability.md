# Reliability Engineering & Operator Runbooks

## Incident Runbook Index

### Schema Breakage Runbook {#schema-breakage-runbook}
1. Inspect `GET /v1/incidents/{id}/evidence` and verify the `SCHEMA_CONTRACT_ERROR` signal pointer and `commit_version` on the upstream Kafka feed.
2. Confirm malformed records are isolated in `bronze.quarantine_dlq` without leaking into `bronze.telemetry_signals`.
3. Approve the OPA-verified `pause_broken_pipeline` plan on the immediate downstream bronze ingestion DAG to prevent corrupting silver/gold tables.
4. Coordinate with the producer owner team to restore backward-compatible Avro schema fields; unpause and replay from the committed stream offset.

### Bad Config / SQL Deployment Runbook {#bad-deploy-runbook}
1. Confirm the `DEPLOYMENT_EVENT` commit precedes the first `LOG_ERROR`/`DQ_FAILURE` in `evidence_pointers`.
2. Review the dry-run preview showing `current_config_version -> last_known_good_version`.
3. Approve via the `approver` role and execute via `operator` in `guarded_active` mode with the generated `idempotency_key`.
4. Verify post-action health check passes (`COMPLETED`); if post-check fails, confirm automatic rollback restored the prior version and escalate to on-call engineering.

### Hallucinated Evidence Response {#hallucinated-evidence-response}
1. Triggered if `sre_hallucinated_citations_total > 0`.
2. Immediately revert `SRE_AGENT_MODE=read_only` and disable `ENABLE_LOCAL_LLM=false`.
3. Inspect `gold.rca_hypotheses` where `hallucinated_citation_count > 0` and verify Iceberg snapshot consistency against `bronze.telemetry_signals` and `silver.asset_lineage_graph`.

### OPA Policy Denial Investigation {#opa-policy-denial-investigation}
1. Query `GET /v1/audit` filtered by `event_type in ("POLICY_DENIED", "EXECUTION_POLICY_DENIED")`.
2. Verify SHA-256 audit hash-chain integrity (`chain_valid == true`).
3. Confirm whether denials originated from unauthorized tool requests, unbounded parameters, or an operator attempting execution without human approval.

### Control Plane Crash / Ephemeral State Recovery
1. Local operational state (`.local_data/state/platform_state.json`) is reconstructible from durable Iceberg V2 storage.
2. Call `RemediationEngine.rebuild_platform_state_from_iceberg()` (verified in Chaos Drill 6) or run `make pipeline` with `--replay` to rebuild operational asset state from `bronze.telemetry_signals` and `gold.remediation_plans`.
