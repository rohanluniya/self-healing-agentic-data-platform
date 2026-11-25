"""OpenTelemetry tracing and Prometheus metrics for the Agentic SRE Control Plane."""

from __future__ import annotations

from collections import deque
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, SpanExporter, SpanExportResult
from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest


class RingBufferSpanExporter(SpanExporter):
    """In-memory bounded ring buffer capturing real OpenTelemetry spans for local inspection."""

    def __init__(self, maxlen: int = 500) -> None:
        self._spans: deque[dict[str, Any]] = deque(maxlen=maxlen)

    def export(self, spans: Any) -> SpanExportResult:
        for span in spans:
            self._spans.append(self._serialize(span))
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        return None

    @staticmethod
    def _serialize(span: ReadableSpan) -> dict[str, Any]:
        ctx = span.get_span_context()
        duration_ms = 0.0
        if span.start_time and span.end_time:
            duration_ms = round((span.end_time - span.start_time) / 1_000_000.0, 3)
        return {
            "name": span.name,
            "trace_id": f"{ctx.trace_id:032x}" if ctx is not None else "",
            "span_id": f"{ctx.span_id:016x}" if ctx is not None else "",
            "parent_span_id": f"{span.parent.span_id:016x}" if span.parent else None,
            "duration_ms": duration_ms,
            "attributes": dict(span.attributes or {}),
            "status": str(span.status.status_code.name),
        }

    def recent(self, limit: int = 25) -> list[dict[str, Any]]:
        items = list(self._spans)
        return items[-limit:]


class TelemetryHub:
    """Holds dedicated Prometheus registry and OpenTelemetry tracer for clean test isolation."""

    def __init__(self, service_name: str = "agentic-sre-control-plane") -> None:
        self.registry = CollectorRegistry()
        self.signals_ingested = Counter(
            "sre_signals_ingested_total",
            "Total telemetry signals ingested into the Iceberg evidence lakehouse",
            ["signal_type", "severity"],
            registry=self.registry,
        )
        self.dlq_quarantined = Counter(
            "sre_dlq_quarantined_total",
            "Total malformed or contract-violating records routed to quarantine DLQ",
            ["reason"],
            registry=self.registry,
        )
        self.incidents_correlated = Counter(
            "sre_incidents_correlated_total",
            "Total correlated incidents produced from raw alerts",
            ["scenario_type", "status"],
            registry=self.registry,
        )
        self.false_positives_suppressed = Counter(
            "sre_false_positives_suppressed_total",
            "Total noisy false-positive alerts suppressed before remediation planning",
            registry=self.registry,
        )
        self.policy_decisions = Counter(
            "sre_opa_policy_decisions_total",
            "Total OPA remediation policy evaluations",
            ["decision", "tool_name", "phase"],
            registry=self.registry,
        )
        self.remediations_executed = Counter(
            "sre_remediations_executed_total",
            "Total remediation executions by tool and final outcome",
            ["tool_name", "outcome"],
            registry=self.registry,
        )
        self.rollbacks_triggered = Counter(
            "sre_rollbacks_total",
            "Total rollbacks triggered (auto post-check failure or manual operator trigger)",
            ["trigger"],
            registry=self.registry,
        )
        self.hallucinated_citations = Counter(
            "sre_hallucinated_citations_total",
            "Count of unverified RCA citations detected by evidence verifier (target 0)",
            registry=self.registry,
        )
        self.rca_latency_seconds = Histogram(
            "sre_rca_latency_seconds",
            "Latency of deterministic correlation and RCA evidence verification",
            buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0),
            registry=self.registry,
        )
        self.active_incidents_gauge = Gauge(
            "sre_active_incidents",
            "Current number of active non-suppressed incidents",
            registry=self.registry,
        )

        self.span_exporter = RingBufferSpanExporter(maxlen=500)
        resource = Resource.create({"service.name": service_name})
        self.tracer_provider = TracerProvider(resource=resource)
        self.tracer_provider.add_span_processor(SimpleSpanProcessor(self.span_exporter))
        self.tracer = self.tracer_provider.get_tracer(service_name)

    @contextmanager
    def start_span(self, name: str, attributes: dict[str, Any] | None = None) -> Iterator[trace.Span]:
        with self.tracer.start_as_current_span(name) as span:
            if attributes:
                for k, v in attributes.items():
                    if v is not None:
                        span.set_attribute(k, v)
            yield span

    def render_prometheus(self) -> bytes:
        return generate_latest(self.registry)

    def recent_traces(self, limit: int = 25) -> list[dict[str, Any]]:
        return self.span_exporter.recent(limit=limit)


DEFAULT_TELEMETRY = TelemetryHub()
