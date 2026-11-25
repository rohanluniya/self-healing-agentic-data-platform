# Incident Postmortem: Bad Deployment Auto-Rollback & Upstream Schema Breakage

## Incident Summary
This postmortem documents two controlled fault-injection drills executed against the Self-Healing Data Platform Control Plane (`results/chaos/chaos_results.json`):
1. **Drill 2 (`bad_config_deployment` with failed post-action verification):** Verifies that when a policy-approved `rollback_config_version` fails its post-action health check, the engine automatically restores `pre_action_snapshot` and records tamper-evident audit proof.
2. **Drill 1 & Local Pipeline (`upstream_broker_outage` & `schema_breakage`):** Verifies cascading multi-hop downstream alerts compress into a single upstream root-cause evidence bundle with zero hallucinated citations.

## Observed Timeline (Chaos Drill 2 — Automatic Rollback)

| Step | Event Type | Actor (Role) | Observed Outcome |
|---|---|---|---|
| 1 | `SIGNAL_INGESTION` | `DurableStreamIngestor` | 5 cascading signals across `silver.orders_enriched`, `gold.daily_revenue_mv`, and `consumer.realtime_fraud_scorer` persisted in `bronze.telemetry_signals` |
| 2 | `CORRELATION_AND_RCA` | `DeterministicRcaEngine` | Compressed 5 alerts -> 1 incident rooted at `silver.orders_enriched` (`commit_version=v2.14.0`); `15 / 15` citations verified (`0.0%` hallucinated) |
| 3 | `DRY_RUN_PROPOSED` | `agent-planner` (`operator`) | OPA verified bounded `rollback_config_version` (`v2.14.0 -> v2.13.4`); status `AWAITING_APPROVAL` |
| 4 | `HUMAN_APPROVED` | `chaos-approver` (`approver`) | Distinct approver verified evidence bundle; status `APPROVED` |
| 5 | `POST_CHECK_FAILED` | `system-verifier` (`system`) | Post-action health probe detected lingering error rate > 5% and DQ drift |
| 6 | `AUTO_ROLLBACK_COMPLETED` | `system-verifier` (`system`) | Automatically restored `pre_action_snapshot` (`v2.14.0`), set plan status to `ROLLED_BACK`, and persisted SHA-256 hash-chained audit record |

## Invariants Verified Post-Recovery
- Asset state matched exact `pre_action_snapshot` (`pre_version == restored_version == v2.14.0`).
- `gold.remediation_audit_log` passed cryptographic SHA-256 chain validation (`verify_audit_hash_chain() == True`).
- Downstream incidents transitioned to `rolled_back` for human escalation without leaving partial mutations behind.

## Follow-Up Actions
- Keep `SRE_AGENT_MODE=read_only` as startup default on all deployments.
- Require canary shadow validation before promoting SQL transforms on `tier0` assets (`silver.orders_enriched`).
