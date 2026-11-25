# System Architecture & Failure Domains

## Overview

The Self-Healing Data Platform Control Plane decouples **incident observation**, **root-cause evidence synthesis**, **policy evaluation**, and **bounded remediation execution** across clear consistency and trust boundaries.

```mermaid
flowchart LR
  subgraph Fixture["Fixture Data Platform (13 Assets)"]
    K["Kafka Feeds\n(orders, payments, clickstream)"]
    B["Bronze Spark Ingest\n(Avro v1/v2 + DLQ)"]
    S["Silver Transforms\n(orders_enriched, user_sessions)"]
    G["Gold Materialized Views\n(daily_revenue_mv, funnel_mv)"]
    C["SLA Consumers\n(BI, Fraud Scorer, Attribution API)"]
    K --> B --> S --> G --> C
  end

  subgraph Lakehouse["Apache Iceberg V2 Evidence Lakehouse (8 Tables)"]
    TS["bronze.telemetry_signals"]
    DLQ["bronze.quarantine_dlq"]
    LG["silver.asset_lineage_graph"]
    CI["silver.correlated_incidents"]
    RCA["gold.rca_hypotheses"]
    PL["gold.remediation_plans"]
    AU["gold.remediation_audit_log\n(SHA-256 Hash Chain)"]
    DQ["quality.dq_results"]
  end

  subgraph ControlPlane["Agentic SRE Control Plane (FastAPI :8060)"]
    CORR["Lineage Correlator +\nFalse-Positive Filter"]
    VER["Deterministic RCA +\nZero-Hallucination Verifier"]
    OPA["OPA Rego v1 Guardrails\n(Default: read_only)"]
    REM["Typed Allowlisted Tools +\nIdempotency + Auto-Rollback"]
    UI["Dark-Mode Operations\nControl Tower + RBAC"]
  end

  Fixture --> TS
  Fixture --> DLQ
  Fixture --> LG
  TS --> CORR
  LG --> CORR
  CORR --> CI
  CI --> VER
  TS --> VER
  VER --> RCA
  RCA --> OPA
  OPA --> REM
  REM --> PL
  REM --> AU
  REM --> Fixture
  Lakehouse --> DQ
  ControlPlane --> UI
```

## Remediation Safety & Rollback Sequence

```mermaid
sequenceDiagram
  participant OP as Operator (RBAC)
  participant API as Control Plane API
  participant OPA as OPA Rego v1 Policy
  participant APPR as Human Approver (RBAC)
  participant PLAT as Fixture Platform State
  participant ICE as Iceberg V2 Audit Log

  OP->>API: POST /v1/remediations/dry-run (tool, asset, params)
  API->>OPA: Evaluate policy (phase=dry_run, allowlist, bounds, FP check)
  OPA-->>API: Decision (ALLOW/DENY + violations + risk_level)
  API->>ICE: Append DRY_RUN_PROPOSED or POLICY_DENIED (SHA-256 linked)
  API-->>OP: Dry-run preview + precondition checks + idempotency_key

  APPR->>API: POST /v1/remediations/{id}/approve
  API->>OPA: Evaluate policy (phase=approve, role=approver)
  API->>ICE: Append HUMAN_APPROVED
  API-->>APPR: Plan status = APPROVED

  OP->>API: POST /v1/remediations/{id}/execute (idempotency_key, guarded_active)
  API->>ICE: Check idempotency_key (at-most-once execution guard)
  API->>OPA: Evaluate policy (phase=execute, SoD, approval, dry-run, mode)
  API->>PLAT: Capture pre_action_snapshot + apply typed tool
  API->>PLAT: Run post-action health verification
  alt Post-check passes
    API->>ICE: Append EXECUTION_VERIFIED (COMPLETED)
    API-->>OP: Plan COMPLETED + post_action_snapshot
  else Post-check fails
    API->>ICE: Append POST_CHECK_FAILED
    API->>PLAT: Automatic rollback -> restore pre_action_snapshot
    API->>ICE: Append AUTO_ROLLBACK_COMPLETED (ROLLED_BACK)
    API-->>OP: Plan ROLLED_BACK (state safely restored)
  end
```

## Lakehouse Storage Modeling (Apache Iceberg V2)

| Table | Layer | Grain | Primary Key | Partition / Maintenance Strategy | Retention |
|---|---|---|---|---|---|
| `bronze.telemetry_signals` | Bronze | One validated telemetry event | `signal_id` | Append/overwrite ZSTD Parquet; compacted to 1 file | 90 days |
| `bronze.quarantine_dlq` | Bronze | One malformed or contract-violating frame | `dlq_id` | Append-only quarantine; compacted periodically | 30 days |
| `silver.asset_lineage_graph` | Silver | One directed OpenLineage edge | `edge_id` | Full snapshot refresh on topology change | Versioned snapshots |
| `silver.correlated_incidents` | Silver | One deduplicated root-cause incident | `incident_id` | Overwrite on incident status transition | 365 days |
| `gold.rca_hypotheses` | Gold | One ranked Top-K root-cause candidate | `hypothesis_id` | Overwrite with verified citation counts | 365 days |
| `gold.remediation_plans` | Gold | One dry-run/approved/executed plan | `plan_id` (`idempotency_key` unique) | Upsert snapshot per lifecycle transition | 365 days |
| `gold.remediation_audit_log` | Gold | One immutable state-transition event | `audit_id` (`seq_no` monotonic) | Append-only SHA-256 hash chain; compacted safely | 7 years (compliance) |
| `quality.dq_results` | Quality | One data quality check execution | `check_id` | Per-run snapshot history for trend tracking | 180 days |

## Failure Domains & Consistency Guarantees

- **At-least-once ingestion, deduplicated lakehouse storage:** `DurableStreamIngestor` supports deterministic replay from offset `0`; exact duplicates are dropped via deterministic `signal_id` before Iceberg commit.
- **Event time vs. processing time:** Correlation windows cluster on `processing_time_ms` (so late-arriving data aligns with downstream reconciliation drift), while root-cause precedence and watermark lag use `event_time_ms`.
- **State loss recovery:** Local operational state (`.local_data/state/platform_state.json`) is disposable; `rebuild_platform_state_from_iceberg()` deterministically reconstructs platform asset state by replaying `bronze.telemetry_signals` and completed `gold.remediation_plans` from Apache Iceberg V2.
- **Read-only fail-safe default:** The control plane boots with `SRE_AGENT_MODE=read_only`. Even an approved plan is blocked by OPA policy until execution explicitly opts into `guarded_active` mode with a distinct operator and approver.
