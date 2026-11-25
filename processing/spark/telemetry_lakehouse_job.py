"""PySpark 4.1 fixture job writing telemetry signals into Apache Iceberg V2 Bronze/Silver tables (distributed profile)."""

from __future__ import annotations

import os


def build_spark_session():  # pragma: no cover - executed inside apache/spark:4.1.4 container
    from pyspark.sql import SparkSession

    lakekeeper_uri = os.getenv("LAKEKEEPER_URI", "http://lakekeeper:8181/catalog")
    rustfs_endpoint = os.getenv("RUSTFS_ENDPOINT", "http://rustfs:9000")
    return (
        SparkSession.builder.appName("agentic-sre-telemetry-lakehouse")
        .config("spark.sql.extensions", "org.apache.iceberg.spark.extensions.IcebergSparkSessionExtensions")
        .config("spark.sql.catalog.sre", "org.apache.iceberg.spark.SparkCatalog")
        .config("spark.sql.catalog.sre.type", "rest")
        .config("spark.sql.catalog.sre.uri", lakekeeper_uri)
        .config("spark.sql.catalog.sre.io-impl", "org.apache.iceberg.aws.s3.S3FileIO")
        .config("spark.sql.catalog.sre.s3.endpoint", rustfs_endpoint)
        .config("spark.sql.catalog.sre.s3.path-style-access", "true")
        .getOrCreate()
    )


def run_spark_telemetry_ingest(input_path: str) -> None:  # pragma: no cover
    spark = build_spark_session()
    try:
        df = spark.read.json(input_path)
        valid_df = df.filter("signal_id IS NOT NULL AND event_time_ms > 0 AND asset_id <> ''")
        invalid_df = df.filter("signal_id IS NULL OR event_time_ms <= 0 OR asset_id = ''")
        valid_df.writeTo("sre.bronze.telemetry_signals").append()
        invalid_df.writeTo("sre.bronze.quarantine_dlq").append()
    finally:
        spark.stop()
