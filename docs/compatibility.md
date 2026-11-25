# Component Compatibility, Licenses & Platform Matrix

## Verified Runtime Environments

| Profile | Target Host | Requirements | Verified Status |
|---|---|---|---|
| `local_native` | macOS ARM64 (Apple Silicon) / Linux x86_64 | Python 3.12.8, `uv` (or `venv`), zero Docker/JVM/OPA binary needed | Verified on macOS 15 ARM64 (Apple M4 Pro, 14 cores, 48 GiB RAM) |
| `standalone` container | Docker Engine / Colima / Linux / macOS | `docker-compose.standalone.yml` (`python:3.12.8-slim-bookworm`) | Manifest pinned & syntax-aligned; container build runs in Docker-enabled CI/hosts |
| `core` / `analytics` / `observability` / `full` | Docker Compose (x86_64 or ARM64 with Rosetta/QEMU for `marquez`) | 8–16 GiB RAM allocated to Docker daemon | All image tags pinned; zero unpinned tags |

## Pinned Python Dependencies & Open-Source Licenses

All Python dependencies are locked in `uv.lock` and audited via `scripts/check_licenses.py` (outputs in `results/security/license_audit.json` and `results/security/sbom.cdx.json`):

| Package | Pinned Version | License | Role |
|---|---|---|---|
| `pyiceberg[sql-sqlite,pyiceberg-core]` | `0.12.0` | Apache-2.0 | Apache Iceberg V2 Incident Evidence Lakehouse |
| `duckdb` | `2.0.0` | MIT | In-process analytical SQL over Iceberg Arrow scans |
| `pyarrow` | `25.0.1` | Apache-2.0 | Columnar Parquet/Arrow serialization |
| `fastavro` | `1.13.1` | MIT | Avro v1/v2 schema contract validation & evolution |
| `fastapi` | `0.163.2` | MIT | Control Plane REST API & RBAC enforcement |
| `uvicorn` | `0.54.0` | BSD-3-Clause | ASGI HTTP server (`127.0.0.1:8060`) |
| `prometheus-client` | `0.26.0` | Apache-2.0 | `/metrics` exposition endpoint |
| `opentelemetry-api` / `opentelemetry-sdk` | `1.45.2` | Apache-2.0 | Distributed trace spans & in-memory ring buffer |
| `matplotlib` | `3.11.2` | PSF / Matplotlib | Benchmark visualization chart export |
| `pytest` / `hypothesis` / `ruff` / `mypy` | Pinned in `pyproject.toml` | MIT / MPL-2.0 | Unit, property, contract, E2E, chaos, lint & static typing |

## Pinned Container Stack (`docker-compose.yml`)

| Service | Pinned Image | License | Compose Profile | Platform Notes |
|---|---|---|---|---|
| Kafka | `apache/kafka:4.3.2` | Apache-2.0 | `core`, `full` | Native ARM64 + AMD64 |
| Apicurio Registry | `apicurio/apicurio-registry:3.3.5` | Apache-2.0 | `core`, `full` | Avro schema registry |
| RustFS | `rustfs/rustfs:1.0.6` | Apache-2.0 | `core`, `full` | S3-compatible object store |
| Lakekeeper | `quay.io/lakekeeper/catalog:v0.15.1` | Apache-2.0 | `core`, `full` | Iceberg REST catalog |
| PostgreSQL / PostGIS | `imresamu/postgis:17-3.6.1-alpine3.23` | PostgreSQL / GPL-2.0 (PostGIS ext) | `core`, `analytics`, `full` | Metadata DB for Lakekeeper, Airflow, Marquez |
| OPA | `openpolicyagent/opa:1.22.3` | Apache-2.0 | `core`, `full` | Rego v1 policy evaluation server |
| Apache Spark | `apache/spark:4.1.4-scala2.13-java17-python3-ubuntu` | Apache-2.0 | `analytics`, `full` | Batch/streaming Bronze/Silver jobs |
| Apache Airflow | `apache/airflow:slim-3.4.0-python3.12` | Apache-2.0 | `analytics`, `full` | Orchestration DAGs |
| Marquez | `marquezproject/marquez:0.51.1` | Apache-2.0 | `analytics`, `full` | Pinned `platform: linux/amd64` (requires emulation on ARM64) |
| OTel Collector | `otel/opentelemetry-collector-contrib:0.166.0-${OTEL_ARCH:-arm64}` | Apache-2.0 | `observability`, `full` | Set `OTEL_ARCH=amd64` on x86_64 |
| Prometheus | `prom/prometheus:v3.16.0` | Apache-2.0 | `observability`, `full` | Metrics scraping & alert rules |
| Loki | `grafana/loki:3.6.22` | AGPL-3.0 (container only) | `observability`, `full` | Optional log aggregation container |
| Grafana | `grafana/grafana:13.0.14` | AGPL-3.0 (container only) | `observability`, `full` | Optional dashboards container |
| Ollama (Optional) | `ollama/ollama:0.40.18` | MIT | `llm` (opt-in only) | Disabled by default; **zero model weights downloaded** |

## Pretrained LLM Weight Policy
No external pretrained LLM weights are downloaded, bundled, or required. The core correlation, RCA, zero-hallucination evidence verifier, and OPA remediation workflow are 100% deterministic. Operators who opt into the `llm` profile must independently review the license of any model weight they choose to pull into Ollama.
