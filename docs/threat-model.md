# Threat Model & Agentic Security Boundaries

## Assets Protected
1. Production data platform tables, pipelines, materialized views, and compute budgets.
2. Incident Evidence Lakehouse (`bronze.*`, `silver.*`, `gold.*`, `quality.*`) and SHA-256 audit log chain.
3. RBAC API credentials and Control Plane remediation endpoints.

## STRIDE-Style Agentic Threat Matrix

| Threat | Attack Vector | Mitigation Implemented | Verification |
|---|---|---|---|
| **Prompt Injection / Unsafe Tool Call** | Adversarial signal message tricks agent into invoking `drop_table`, `delete_prod_data`, or `shell_exec` | Deterministic RCA never lets untrusted text choose tool names; OPA Rego v1 hard-denies all forbidden & unlisted tools | `tests/unit/test_opa_policy.py`, Hypothesis properties, Chaos Drill 3 |
| **Privilege Escalation / Self-Approval** | Operator attempts to approve own remediation or Viewer attempts mutation | Separate RBAC API keys (`viewer`, `operator`, `approver`) + OPA separation-of-duties (`operator_id != approver_id`) | `tests/e2e/test_control_plane_api.py` (401/403 assertions) |
| **Runaway Cost / Unbounded Backfill** | Agent triggers 365-partition backfill or infinite retries | OPA Rego enforces `1 <= max_retries <= 3`, `1 <= partition_count <= 24`, `timeout_seconds <= 900` | Hypothesis property tests & adversarial benchmark probes |
| **Alert-Noise Mutation (False Positive)** | Transient single-sample latency jitter triggers unnecessary pipeline pause | Persistence filter suppresses isolated WARNING spikes; OPA hard-denies mutations where `incident_is_false_positive == true` | Chaos Drill 5, DQ check `false_positive_zero_mutation` |
| **Duplicate Execution under Retries** | Network timeout causes operator/agent to fire `execute` twice | Global `idempotency_key` check persisted in Iceberg V2 guarantees at-most-once execution | Chaos Drill 4, Hypothesis idempotency property |
| **Hallucinated Evidence Fabrication** | Diagnosis claims nonexistent trace span or commit SHA | Every citation is verified against persisted Iceberg V2 records (`0.0%` hallucinated evidence rate) | `verify_evidence_pointers()`, DQ check `rca_zero_hallucinated_citations` |
| **Audit Log Tampering** | Malicious actor alters historical remediation outcome | Sequential SHA-256 hash chain (`seq_no`, `prev_hash`, `entry_hash`) persisted in Iceberg V2 | Chaos Drill 8, `verify_audit_hash_chain()` |
| **Secret Leakage in Logs** | API keys, bearer tokens, PATs, or emails appear in error strings | Regex redaction (`redact_sensitive()`) applied in JSON logger and DLQ ingestor | `tests/unit/test_correlator_and_rca.py` |

## Development vs. Production Security Boundaries
- **Development default keys** in `.env.example` (`dev-viewer-key-readonly`, `dev-operator-key-ops`, `dev-approver-key-gov`) are strictly for local evaluation and automated tests. Production deployments must replace them with OIDC/JWT + short-lived mTLS or KMS-backed secrets, enable TLS termination in front of FastAPI/OPA, and enforce write-once object lock (WORM) on the S3 bucket backing `gold.remediation_audit_log`.
