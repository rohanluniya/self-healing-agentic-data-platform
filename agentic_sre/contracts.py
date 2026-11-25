"""Avro v1/v2 contract validation, deterministic IDs, and event-time semantics."""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
from typing import Any

import fastavro

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = REPO_ROOT / "schemas" / "avro"


class ContractValidationError(ValueError):
    """Raised when an incoming telemetry event fails Avro schema validation."""


class AvroContractRegistry:
    """Loads pinned Avro v1 and v2 schemas and enforces evolution & validation."""

    def __init__(self, schema_dir: Path | None = None) -> None:
        base = schema_dir or SCHEMA_DIR
        self.v1_raw = json.loads((base / "telemetry_signal_v1.avsc").read_text(encoding="utf-8"))
        self.v2_raw = json.loads((base / "telemetry_signal_v2.avsc").read_text(encoding="utf-8"))
        self.v1_schema = fastavro.parse_schema(self.v1_raw)
        self.v2_schema = fastavro.parse_schema(self.v2_raw)

    def validate(self, record: dict[str, Any], version: int = 2) -> dict[str, Any]:
        """Validate a signal dict against Avro v1 or v2 and return canonical v2 dict."""
        schema = self.v1_schema if version == 1 else self.v2_schema
        try:
            fastavro.validate(record, schema, raise_errors=True)
        except Exception as exc:
            raise ContractValidationError(f"Avro v{version} validation failed: {exc}") from exc

        if record.get("event_time_ms", 0) <= 0 or record.get("processing_time_ms", 0) <= 0:
            raise ContractValidationError("Timestamps event_time_ms and processing_time_ms must be positive")
        if not str(record.get("asset_id", "")).strip():
            raise ContractValidationError("asset_id must be non-empty")

        canonical = dict(record)
        canonical.setdefault("cost_usd_delta", 0.0)
        canonical.setdefault("is_retraction", False)
        canonical.setdefault("lineage_job_name", None)
        canonical.setdefault("producer_service", None)
        return canonical

    def serialize(self, record: dict[str, Any], version: int = 2) -> bytes:
        schema = self.v1_schema if version == 1 else self.v2_schema
        buf = io.BytesIO()
        fastavro.schemaless_writer(buf, schema, record)
        return buf.getvalue()

    def deserialize(self, payload: bytes, writer_version: int = 1, reader_version: int = 2) -> dict[str, Any]:
        writer = self.v1_schema if writer_version == 1 else self.v2_schema
        reader = self.v1_schema if reader_version == 1 else self.v2_schema
        buf = io.BytesIO(payload)
        decoded = fastavro.schemaless_reader(buf, writer, reader)
        if not isinstance(decoded, dict):
            raise ContractValidationError("Decoded Avro payload is not a record mapping")
        return dict(decoded)


def deterministic_signal_id(
    scenario_tag: str,
    asset_id: str,
    signal_type: str,
    event_time_ms: int,
    sequence_idx: int,
) -> str:
    """Produce a deterministic, replay-stable signal identifier."""
    raw = f"{scenario_tag}|{asset_id}|{signal_type}|{event_time_ms}|{sequence_idx}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    return f"sig-{digest}"


def deterministic_incident_id(root_asset: str, scenario_type: str, bucket_window: str) -> str:
    """Produce a deterministic correlated incident identifier."""
    raw = f"{root_asset}|{scenario_type}|{bucket_window}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    return f"inc-{digest}"


def compute_event_lag_seconds(event_time_ms: int, processing_time_ms: int) -> float:
    """Compute processing-time minus event-time lag in seconds."""
    return round((processing_time_ms - event_time_ms) / 1000.0, 3)
