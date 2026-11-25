# Requirements & Service-Level Objectives

## Functional Requirements
1. **Fixture Data Platform & 9 Adversarial Failure Injectors:** Simulate a 5-layer interconnected DAG (`Kafka -> Bronze Spark -> Silver -> Gold MVs -> SLA Consumers`) with deterministic failure injection covering schema breakage, stale tables, retry storms, bad deployments, partition-skew cost spikes, late-arriving data, missing partitions, upstream broker outages, and false-positive noisy alerts.
2. **Incident Evidence Lakehouse (Apache Iceberg V2):** Persist telemetry signals, quarantined DLQ records, OpenLineage edges, correlated incidents, RCA hypotheses, remediation plans, hash-chained audit logs, and data quality checks across 8 Apache Iceberg V2 tables with snapshot time travel and compaction.
3. **Cross-Asset Correlation & Zero-Hallucination RCA:** Compress cascading alert storms into single upstream root causes, suppress isolated transient warning spikes, and verify every RCA evidence pointer (`signal_id`, `span_id`, `commit_version`, `lineage_edge`) against persisted Iceberg records (`0.0%` hallucinated evidence rate).
4. **OPA Policy Guardrails & Typed Allowlisted Tools:** Default to read-only diagnosis (`SRE_AGENT_MODE=read_only`); hard-deny destructive/unlisted tools (`drop_table`, `delete_prod_data`, `shell_exec`, unbounded backfills); require dry-run preview, precondition checks, human approval with separation of duties (`operator != approver`), idempotency keys, post-action health verification, and automatic rollback.
5. **Control Plane API & Interactive Dashboard:** Serve RBAC-protected REST endpoints (`viewer`, `operator`, `approver`), Prometheus `/metrics`, OpenTelemetry spans, and an interactive dark-mode Operations Control Tower on `127.0.0.1:8060`.

## Service-Level Objectives (SLOs)

| Objective | Target | Measurement Source |
|---|---|---|
| Hallucinated Evidence Rate | `0.0%` (strict zero) | `gold.rca_hypotheses` & `quality.dq_results` |
| Unsafe / Unlisted Action Rejection | `100.0%` | OPA Rego v1 policy evaluation & adversarial suite |
| False-Positive Non-Mutation Rate | `100.0%` | `quality.dq_results` (`false_positive_zero_mutation`) |
| Rollback Success Rate | `100.0%` | Auto & manual rollback verification in chaos & benchmarks |
| Deterministic Correlation + RCA Latency (p95) | `< 50 ms` | `benchmarks/run_benchmarks.py` (`sre_rca_latency_seconds`) |
| Immutable Audit Hash-Chain Integrity | `100%` verified | `verify_audit_hash_chain()` & `/v1/audit` |
| Data Quality Suite Pass Rate | `7 / 7` checks passing | `quality.dq_results` |
