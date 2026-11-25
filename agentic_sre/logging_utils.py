"""Structured JSON logging with trace/correlation/run IDs and secret redaction."""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_REDACT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*[^\s,;\"']+"), r"\1=[REDACTED]"),
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]+"), "Bearer [REDACTED]"),
    (re.compile(r"github" r"_pat_[A-Za-z0-9_]+"), "[REDACTED_PAT]"),
    (re.compile(r"dev-(viewer|operator|approver)-key-[a-z]+"), "[REDACTED_KEY]"),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[REDACTED_EMAIL]"),
]


def redact_sensitive(text: str) -> str:
    """Redact credentials, tokens, API keys, and emails before logging or persistence."""
    cleaned = text
    for pattern, replacement in _REDACT_PATTERNS:
        cleaned = pattern.sub(replacement, cleaned)
    return cleaned


class StructuredJsonFormatter(logging.Formatter):
    """Emit structured JSON log lines with trace, correlation, and run identifiers."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_sensitive(record.getMessage()),
            "trace_id": getattr(record, "trace_id", None),
            "correlation_id": getattr(record, "correlation_id", None),
            "run_id": getattr(record, "run_id", None),
            "component": getattr(record, "component", "control-plane"),
        }
        extra_fields = getattr(record, "extra_fields", None)
        if isinstance(extra_fields, dict):
            payload["details"] = {
                k: redact_sensitive(str(v)) if isinstance(v, str) else v
                for k, v in extra_fields.items()
            }
        return json.dumps(payload, separators=(",", ":"))


def get_logger(name: str, log_file: Path | None = None) -> logging.Logger:
    """Return a structured JSON logger with optional durable file sink."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(StructuredJsonFormatter())
        logger.addHandler(stream_handler)
        logger.propagate = False
    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        abs_path = str(log_file.resolve())
        existing = [
            h for h in logger.handlers
            if isinstance(h, logging.FileHandler) and h.baseFilename == abs_path
        ]
        if not existing:
            fh = logging.FileHandler(abs_path, encoding="utf-8")
            fh.setFormatter(StructuredJsonFormatter())
            logger.addHandler(fh)
    return logger
