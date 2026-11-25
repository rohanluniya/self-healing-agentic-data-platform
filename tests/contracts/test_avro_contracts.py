"""Contract tests for Avro v1/v2 backward-compatible schema evolution, DLQ quarantine, and stream replay."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentic_sre.contracts import AvroContractRegistry, ContractValidationError
from ingestion.kafka_dlq_ingestor import DurableStreamIngestor
from ingestion.signal_generator import generate_scenario_signals


def test_avro_v1_payload_backward_compatible_with_v2_reader() -> None:
    registry = AvroContractRegistry()
    v1_record = {
        "signal_id": "sig-v1-compat-001",
        "signal_type": "LOG_ERROR",
        "asset_id": "bronze.orders_raw",
        "severity": "ERROR",
        "event_time_ms": 1_795_435_200_000,
        "processing_time_ms": 1_795_435_200_250,
        "trace_id": "a" * 32,
        "span_id": "b" * 16,
        "run_id": "run-v1-compat",
        "scenario_tag": "compat_test",
        "metric_name": None,
        "metric_value": None,
        "message": "Legacy v1 producer error payload",
        "commit_version": "v1.0.0",
        "partition_key": None,
        "schema_version": 1,
    }
    raw_bytes = registry.serialize(v1_record, version=1)
    upgraded = registry.deserialize(raw_bytes, writer_version=1, reader_version=2)
    assert upgraded["signal_id"] == "sig-v1-compat-001"
    assert upgraded["cost_usd_delta"] == 0.0
    assert upgraded["is_retraction"] is False
    assert upgraded["lineage_job_name"] is None
    assert upgraded["producer_service"] is None


def test_avro_contract_rejects_invalid_enum_and_negative_timestamp() -> None:
    registry = AvroContractRegistry()
    bad = {
        "signal_id": "sig-bad-01",
        "signal_type": "NOT_A_VALID_TYPE",
        "asset_id": "bronze.orders_raw",
        "severity": "ERROR",
        "event_time_ms": -100,
        "processing_time_ms": 100,
        "trace_id": "a" * 32,
        "span_id": "b" * 16,
        "run_id": "run-bad",
        "scenario_tag": "bad",
        "message": "bad",
        "schema_version": 2,
    }
    with pytest.raises(ContractValidationError):
        registry.validate(bad, version=2)


def test_durable_ingestor_deduplicates_quarantines_and_replays(tmp_path: Path) -> None:
    ingestor = DurableStreamIngestor(tmp_path / "raw_stream")
    batch = generate_scenario_signals(
        "schema_breakage",
        seed=11,
        include_duplicates=True,
        include_malformed=True,
    )
    ingestor.publish(batch, truncate=True)

    first = ingestor.consume(replay=False)
    assert len(first.valid_signals) == 5
    assert first.duplicate_count == 1
    assert len(first.quarantined_records) == 1

    # Subsequent consume without new data reads 0 new records (offset persisted)
    empty = ingestor.consume(replay=False)
    assert empty.total_received == 0
    assert len(empty.valid_signals) == 0

    # Full replay from offset 0 reproduces exact same signal IDs deterministically
    replayed = ingestor.consume(replay=True)
    assert [s["signal_id"] for s in replayed.valid_signals] == [s["signal_id"] for s in first.valid_signals]
    assert len(replayed.quarantined_records) == 1
