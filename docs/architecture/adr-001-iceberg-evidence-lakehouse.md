# ADR-001: Apache Iceberg V2 as the Incident Evidence Lakehouse

## Status
Accepted

## Context
An agentic operations control plane must store raw telemetry signals, malformed DLQ payloads, lineage edges, correlated incidents, RCA hypotheses, remediation plans, and cryptographic audit logs with full version history, snapshot isolation, schema enforcement, and analytical queryability.

## Decision
Use **Apache Iceberg V2** (`format-version: 2`, ZSTD Parquet) managed through `pyiceberg` (`SqlCatalog` backed by SQLite in `local_native` mode; `Lakekeeper` REST catalog + `RustFS` S3 in `distributed` mode), paired with **DuckDB** for zero-copy analytical SQL over Arrow scans.

## Consequences
- **Benefits:** Atomic snapshot commits, built-in time travel (`snapshot_id`), explicit compaction removing small-file fragmentation, zero JVM requirement for local execution, and clean portability to Spark 4.1 + Lakekeeper in distributed clusters.
- **Tradeoffs:** Iceberg table scans across multiple appended Parquet files do not guarantee row insertion order. We explicitly solved this by adding a monotonic `seq_no` column to `gold.remediation_audit_log` and sorting by `seq_no` before hash-chain verification and append operations.
