"""Durable stream ingestor with Avro v1/v2 validation, replay, deduplication, and DLQ quarantine."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agentic_sre.contracts import AvroContractRegistry, ContractValidationError
from agentic_sre.logging_utils import redact_sensitive
from agentic_sre.telemetry import DEFAULT_TELEMETRY, TelemetryHub


@dataclass
class IngestionResult:
    valid_signals: list[dict[str, Any]]
    quarantined_records: list[dict[str, Any]]
    duplicate_count: int
    retraction_count: int
    total_received: int
    last_offset: int


class DurableStreamIngestor:
    """Append-only durable local topic log with offset tracking, replay, and DLQ quarantine."""

    def __init__(
        self,
        raw_stream_dir: Path,
        registry: AvroContractRegistry | None = None,
        telemetry: TelemetryHub | None = None,
    ) -> None:
        self.raw_stream_dir = raw_stream_dir
        self.raw_stream_dir.mkdir(parents=True, exist_ok=True)
        self.topic_file = self.raw_stream_dir / "telemetry_topic.jsonl"
        self.dlq_file = self.raw_stream_dir / "quarantine_dlq.jsonl"
        self.offset_file = self.raw_stream_dir / "offsets.json"
        self.registry = registry or AvroContractRegistry()
        self.telemetry = telemetry or DEFAULT_TELEMETRY

    def publish(self, records: list[dict[str, Any]], truncate: bool = False) -> int:
        """Append raw records to durable topic log (simulating Kafka topic durability)."""
        mode = "w" if truncate else "a"
        with self.topic_file.open(mode, encoding="utf-8") as fh:
            for rec in records:
                fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
        if truncate and self.offset_file.exists():
            self.offset_file.unlink()
        if truncate and self.dlq_file.exists():
            self.dlq_file.unlink()
        return len(records)

    def _read_offset(self) -> int:
        if not self.offset_file.exists():
            return 0
        data = json.loads(self.offset_file.read_text(encoding="utf-8"))
        return int(data.get("telemetry_topic_offset", 0))

    def _save_offset(self, offset: int) -> None:
        self.offset_file.write_text(
            json.dumps(
                {
                    "telemetry_topic_offset": offset,
                    "updated_at": datetime.now(UTC).isoformat(),
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    def consume(self, replay: bool = False) -> IngestionResult:
        """Consume from committed offset (or offset 0 on replay), validating Avro v1/v2 and routing faults to DLQ."""
        if not self.topic_file.exists():
            return IngestionResult([], [], 0, 0, 0, 0)

        start_offset = 0 if replay else self._read_offset()
        lines = self.topic_file.read_text(encoding="utf-8").splitlines()

        valid: list[dict[str, Any]] = []
        quarantined: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        dup_count = 0
        retraction_count = 0

        with self.telemetry.start_span(
            "ingestion.consume_stream",
            {"replay": replay, "start_offset": start_offset, "total_lines": len(lines)},
        ):
            for offset in range(start_offset, len(lines)):
                raw_line = lines[offset]
                try:
                    raw_obj = json.loads(raw_line)
                except json.JSONDecodeError as exc:
                    qrec = {
                        "dlq_id": f"dlq-offset-{offset}",
                        "offset": offset,
                        "reason": f"json_decode_error: {exc}",
                        "raw_payload": redact_sensitive(raw_line[:1000]),
                        "quarantined_at": datetime.now(UTC).isoformat(),
                    }
                    quarantined.append(qrec)
                    self.telemetry.dlq_quarantined.labels(reason="json_decode_error").inc()
                    continue

                version = int(raw_obj.get("schema_version", 2))
                try:
                    canonical = self.registry.validate(raw_obj, version=1 if version == 1 else 2)
                except ContractValidationError as exc:
                    qrec = {
                        "dlq_id": f"dlq-offset-{offset}",
                        "offset": offset,
                        "reason": str(exc),
                        "raw_payload": redact_sensitive(json.dumps(raw_obj)[:1000]),
                        "quarantined_at": datetime.now(UTC).isoformat(),
                    }
                    quarantined.append(qrec)
                    self.telemetry.dlq_quarantined.labels(reason="avro_contract_violation").inc()
                    continue

                sig_id = canonical["signal_id"]
                if sig_id in seen_ids:
                    dup_count += 1
                    continue
                seen_ids.add(sig_id)

                if canonical.get("is_retraction"):
                    retraction_count += 1

                canonical["message"] = redact_sensitive(canonical["message"])
                canonical["stream_offset"] = offset
                valid.append(canonical)
                self.telemetry.signals_ingested.labels(
                    signal_type=canonical["signal_type"],
                    severity=canonical["severity"],
                ).inc()

        if quarantined:
            with self.dlq_file.open("w" if replay else "a", encoding="utf-8") as dfh:
                for q in quarantined:
                    dfh.write(json.dumps(q, separators=(",", ":")) + "\n")

        self._save_offset(len(lines))
        return IngestionResult(
            valid_signals=valid,
            quarantined_records=quarantined,
            duplicate_count=dup_count,
            retraction_count=retraction_count,
            total_received=len(lines) - start_offset,
            last_offset=len(lines),
        )
