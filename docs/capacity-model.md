# Capacity Model & Scaling Envelope

## Measured vs. Simulated Scale Separation
All benchmark results in `results/benchmarks/` explicitly separate **measured local execution** (real PyIceberg V2 Parquet writes, DuckDB scans, Avro validation, and OPA policy checks on Apple M4 Pro) from **production scaling estimates** below.

## Local Resource Budget (`local_native` & `standalone`)

| Workload Profile | Signals / Batch | Correlated Incidents | Disk Footprint (Iceberg V2 + WAL) | Peak RSS Memory |
|---|---|---|---|---|
| `smoke` | 32 valid (+2 DLQ, +2 dup) | 9 (8 actionable, 1 FP) | `< 4 MB` | `~140 MB` |
| `local` | 32 valid (+2 DLQ, +2 dup) | 9 (8 actionable, 1 FP) | `< 6 MB` | `~155 MB` |
| `stress` | 182 valid (+2 DLQ, +2 dup) | 54 (48 actionable, 6 FP) | `< 15 MB` | `~190 MB` |

## Distributed Compose Profile Budgets (`docker-compose.yml`)

| Profile | Active Services | Recommended Host RAM | Notes |
|---|---|---|---|
| `core` | Kafka, Apicurio, RustFS, PostGIS, Lakekeeper, OPA, Control Plane | `6 GiB` | Core event bus, Iceberg REST catalog, and remote OPA server |
| `analytics` | PostGIS, Spark 4.1, Airflow 3.4, Marquez | `6 GiB` | Batch ingestion, DAG scheduling, OpenLineage catalog |
| `observability` | OTel Collector, Prometheus, Loki, Grafana | `3 GiB` | Full metrics, traces, and dashboards |
| `full` | All core + analytics + observability services | `14–16 GiB` | Complete distributed stack |
| `llm` (opt-in) | Ollama (`ollama/ollama:0.40.18`) | `+4–8 GiB` | Optional read-only narration; zero weights bundled |

## Storage Growth & Compaction Policy
- Append-heavy tables (`bronze.telemetry_signals` and `gold.remediation_audit_log`) accumulate one Parquet data file per commit.
- Running periodic Iceberg V2 compaction (`services/pipeline/run_pipeline.py --compact` or Airflow DAG task `compact_iceberg_evidence_tables`) collapses fragmented small files into a single ZSTD-compressed Parquet file per partition, reducing scan overhead dramatically as measured in `results/benchmarks/benchmark_summary.json`.
