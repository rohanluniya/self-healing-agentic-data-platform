"""Airflow 3.4 DAG orchestrating fixture platform pipelines and Agentic SRE observation/compaction."""

from __future__ import annotations

from datetime import datetime, timedelta

try:
    from airflow import DAG
    from airflow.operators.bash import BashOperator
except ImportError:  # pragma: no cover - Airflow runs inside distributed Docker profile
    DAG = None
    BashOperator = None

DEFAULT_ARGS = {
    "owner": "data-reliability-sre",
    "depends_on_past": False,
    "retries": 2,
    "retry_delay": timedelta(minutes=2),
    "execution_timeout": timedelta(minutes=15),
}

if DAG is not None and BashOperator is not None:
    with DAG(
        dag_id="self_healing_data_platform_ops",
        description="Ingest telemetry, correlate incidents via OpenLineage, run zero-hallucination RCA, and compact Iceberg V2 tables",
        default_args=DEFAULT_ARGS,
        start_date=datetime(2026, 11, 1),
        schedule="*/15 * * * *",
        catchup=False,
        max_active_runs=1,
        tags=["agentic-sre", "iceberg-v2", "opa", "openlineage"],
    ) as dag:
        ingest_and_correlate = BashOperator(
            task_id="ingest_correlate_and_diagnose",
            bash_command="python /app/services/pipeline/run_pipeline.py --profile local",
        )

        iceberg_maintenance = BashOperator(
            task_id="compact_iceberg_evidence_tables",
            bash_command="python /app/services/pipeline/run_pipeline.py --profile local --replay --compact",
        )

        verify_policy_tests = BashOperator(
            task_id="verify_opa_rego_invariants",
            bash_command="pytest -q /app/tests/unit/test_opa_policy.py",
        )

        ingest_and_correlate >> iceberg_maintenance >> verify_policy_tests
