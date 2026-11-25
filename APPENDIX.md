# Engineering Appendix: Ablations, Acceptance Matrix, Chaos Drills & Caveats

This appendix captures engineering diagnostics, bugs resolved during verification, the full 15-item Mandatory Acceptance Matrix, chaos fault-injection evidence, adversarial OPA evaluation details, and extended scope caveats so `README.md` remains concise.

---

## 1. Engineering Diagnostics & Real Bugs Fixed During Verification

| Issue Observed | Root Cause | Resolution Applied | Measured Verification |
|---|---|---|---|
| **Iceberg V2 Audit Hash Chain Failure** | Sequential `append()` commits to `gold.remediation_audit_log` produced separate Parquet files; Iceberg table scans returned files in manifest order rather than chronological insertion order, breaking `prev_hash` linkage | Added monotonic `seq_no` (`int64`) to `gold.remediation_audit_log`, sorted rows by `seq_no` before computing `prev_hash` and verifying the SHA-256 chain | `audit_log_hash_chain_integrity` passes `10/10` entries before and after compaction; Chaos Drill 8 catches single-field tampering |
| **Avro v1 -> v2 Schema Resolution Failure** | Naming records `TelemetrySignalV1` and `TelemetrySignalV2` violated Avro fullname matching during reader-writer resolution | Standardized canonical Avro names (`TelemetrySignal`, `SignalType`, `Severity`) across both `v1` and `v2` schemas with defaults on new v2 fields | `test_avro_v1_payload_backward_compatible_with_v2_reader` passes cleanly |
| **Small-File Scan Degradation in Iceberg V2** | 25 micro-batch appends to `bronze.telemetry_signals` created 25 separate Parquet files (`30.35 ms` mean scan across 5 reads) | Added `IcebergEvidenceLakehouse.compact_table()` rewriting fragmented files into a single ZSTD Parquet file | Reduced 25 files -> 1 file and scan latency from `30.35 ms` -> `2.92 ms` (**10.41× faster scan** vs. uncompacted baseline) |
| **Audit-Log File Fragmentation** | 10 sequential audit appends in local pipeline run created 10 small Parquet files (`10.29 ms` read) | Included `gold.remediation_audit_log` in `--compact` maintenance pass | Reduced 10 files -> 1 file (`10.29 ms` -> `2.16 ms`, **4.77× faster**) while preserving SHA-256 chain |

---

## 2. Full 15-Item Mandatory Acceptance Matrix

| # | Mandatory Acceptance Criterion | Verification Artifact / Command | Measured Outcome |
|---|---|---|---|
| 1 | Fresh-clone setup starts core stack & verifies service health | `./scripts/run_portable.sh local` + `GET http://127.0.0.1:8060/health` | **PASS** — HTTP 200, 8 Iceberg V2 tables ready, `default_agent_mode=read_only` |
| 2 | Deterministic input generation produces identical event IDs for same seed | `tests/unit/test_correlator_and_rca.py::test_deterministic_seed_produces_identical_ids` | **PASS** — Byte-identical `signal_id` and `span_id` sequences |
| 3 | Real ingestion persists source data with metadata & replay capability | `tests/contracts/test_avro_contracts.py::test_durable_ingestor_deduplicates_quarantines_and_replays` | **PASS** — Offset persistence + deterministic replay from offset 0 |
| 4 | Core domain transformation yields correct results for known fixtures | `tests/unit/test_correlator_and_rca.py` (all 9 parametrized scenarios) | **PASS** — 9/9 exact root asset & category matches |
| 5 | Domain-specific advanced capabilities operational end-to-end with integration tests | `tests/integration/test_lakehouse_and_pipeline.py` + `tests/e2e/test_control_plane_api.py` | **PASS** — Lineage correlation, zero-hallucination RCA, OPA, approval, auto-rollback |
| 6 | Duplicates, late events, and retractions follow documented semantics | `ingestion/kafka_dlq_ingestor.py`, `agentic_sre/correlator.py`, `tests/contracts/` | **PASS** — Exact duplicates dropped, retractions excluded, 4h late data clustered via `processing_time_ms` |
| 7 | Service crash and restart recovers according to tested guarantee | Chaos Drill 6 (`test_drill_06_control_plane_state_loss_and_iceberg_rebuild`) | **PASS** — Deleted `platform_state.json` rebuilt identically from Iceberg V2 |
| 8 | Backfill or replay produces reconcilable results | Chaos Drill 7 + `test_iceberg_time_travel_and_compaction_preserve_row_counts` | **PASS** — Exact row reconciliation across replay, snapshots, and compaction |
| 9 | Primary API/dashboard returns real computed outputs & freshness | `GET /v1/overview`, `GET /v1/incidents/{id}/evidence`, Control Tower UI screenshots | **PASS** — Live DuckDB/Iceberg metrics, freshness timestamps, verified UI PNGs |
| 10 | Data quality checks catch injected invalid inputs & retain quarantine DLQ | `quality.dq_results` (`7/7 PASS`), `bronze.quarantine_dlq` (`2` malformed records, `0` leaked) | **PASS** — All 7 governance/DQ checks pass |
| 11 | Observability contains actual logs, metrics, and traces | JSON logs (`.local_data/logs/control_plane.jsonl`), `/metrics`, OTel `recent_traces` | **PASS** — Structured redacted JSON logs, Prometheus metrics, real OTel spans |
| 12 | Access control rejects unauthorized requests | `tests/e2e/test_control_plane_api.py::test_rbac_blocks_missing_invalid_and_cross_role_requests` | **PASS** — 401 on missing/bad key; 403 on `viewer->dry-run`, `operator->approve`, `approver->execute` |
| 13 | Controlled failure produces incident report with observed recovery | `docs/incidents/incident-postmortem-schema-breakage-and-auto-rollback.md` + Chaos Drill 2 | **PASS** — Post-check failure triggered automatic snapshot restoration |
| 14 | Benchmark records hardware, input volume, commands, latency/throughput & raw outputs | `benchmarks/run_benchmarks.py` -> `results/benchmarks/*.{json,csv}` | **PASS** — All profiles, labeled suite, MTTR, and compaction measured |
| 15 | CI and tests execute with honest disclosure of limitations | `50/50 pytest`, `ruff`, `mypy`, `check_licenses.py`, `docs/limitations.md` | **PASS** — Zero hidden mocks; Docker/OPA-CLI host limitations explicitly disclosed |

---

## 3. Automated Chaos & Fault-Injection Drills (8 / 8 Passed)

Raw evidence: [`results/chaos/chaos_results.json`](results/chaos/chaos_results.json)

| Drill ID | Failure Injected | Invariant Verified | Elapsed |
|---|---|---|---|
| `drill_01_cascading_upstream_outage` | 4-hop Kafka broker outage storm | Compressed `4 -> 1` incident rooted at `kafka.payments_events`; `0` hallucinated citations | 0.54 ms |
| `drill_02_auto_rollback_failed_post_check` | Bad deployment rollback with failing post-action health check | Auto-rollback restored `v2.14.0` pre-action snapshot; logged `POST_CHECK_FAILED` + `AUTO_ROLLBACK_COMPLETED` | 772.87 ms |
| `drill_03_opa_unsafe_action_denial` | `drop_table`, `delete_prod_data`, `shell_exec`, 500-part backfill | `4 / 4` (100%) denied by OPA policy; zero mutations | 717.19 ms |
| `drill_04_idempotent_approval_and_execution` | Duplicate approval + 3× identical execute calls | `execution_count == 1`; 2 duplicate calls guarded as replays | 667.50 ms |
| `drill_05_false_positive_suppression` | 5 noisy single-sample warning spikes + mutation attempt on FP | `5 / 5` suppressed; OPA hard-denied mutation attempt | 531.37 ms |
| `drill_06_state_loss_iceberg_rebuild` | Deleted `platform_state.json` on disk | Reconstructed all 13 assets & completed MV refresh cleanly from Iceberg V2 | 607.10 ms |
| `drill_07_malformed_dlq_quarantine_replay` | Corrupted JSON + invalid Avro enum + duplicate frame | `2` malformed isolated in DLQ, `1` duplicate dropped, exact replay parity | 2.41 ms |
| `drill_08_audit_hash_chain_tamper_detection` | Single-field mutation on persisted audit record | SHA-256 hash chain passed intact (`10` entries) and detected tampering immediately | 597.32 ms |

---

## 4. Adversarial OPA Unsafe-Action Benchmark Probes (8 / 8 Rejected)

| Probe ID | Requested Tool / Action | Phase | OPA Verdict | Policy Violation(s) Triggered |
|---|---|---|---|---|
| `adv-01-drop-table` | `drop_table` | `dry_run` | **DENY** | `forbidden_destructive_tool:drop_table` |
| `adv-02-delete-prod-data` | `delete_prod_data` | `execute` | **DENY** | `forbidden_destructive_tool:delete_prod_data` |
| `adv-03-shell-exec` | `shell_exec` | `dry_run` | **DENY** | `forbidden_destructive_tool:shell_exec` |
| `adv-04-unbounded-backfill` | `backfill_partition` (`365` partitions) | `dry_run` | **DENY** | `backfill_partition_limit_exceeded` |
| `adv-05-excessive-retries` | `bounded_retry_task` (`50` retries) | `dry_run` | **DENY** | `retry_limit_exceeded` |
| `adv-06-execute-without-approval` | `rollback_config_version` (`approved=false`) | `execute` | **DENY** | `human_approval_required` |
| `adv-07-mutate-false-positive` | `pause_broken_pipeline` (`is_fp=true`) | `dry_run` | **DENY** | `false_positive_incident_cannot_mutate` |
| `adv-08-read-only-execute-bypass` | `rebuild_materialized_view` (`agent_mode=read_only`) | `execute` | **DENY** | `read_only_mode_blocks_execution` |

---

## 5. Extended Scope & Caveats
- **Local vs. Distributed Execution:** All measured metrics were executed natively on macOS ARM64 (`Apple M4 Pro`, Python `3.12.8`) without Docker, JVM, or standalone `opa` binary. The multi-profile `docker-compose.yml` (`core`, `analytics`, `observability`, `full`, optional `llm`) and `docker-compose.standalone.yml` pin every container image tag and run `opa test` via `openpolicyagent/opa:1.22.3` in GitHub Actions CI.
- **No Downloaded Pretrained Models:** Zero external LLM weights are downloaded or evaluated; `OptionalLocalLLMAdapter` defaults to disabled (`ENABLE_LOCAL_LLM=false`).
- **License & SBOM Audit:** `scripts/check_licenses.py` audited **67** installed Python packages with **0** copyleft/proprietary flags (`results/security/license_audit.json`, `results/security/sbom.cdx.json`).
