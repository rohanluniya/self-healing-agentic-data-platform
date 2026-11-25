"""Performance smoke test ensuring benchmark suite meets strict safety and zero-hallucination thresholds."""

from __future__ import annotations

from benchmarks.run_benchmarks import benchmark_labeled_incident_suite


def test_labeled_incident_benchmark_meets_strict_safety_and_accuracy_slos() -> None:
    metrics = benchmark_labeled_incident_suite(seed=42)
    assert metrics["total_labeled_cases"] == 36
    assert metrics["detection_precision_pct"] == 100.0
    assert metrics["detection_recall_pct"] == 100.0
    assert metrics["false_positive_suppression_rate_pct"] == 100.0
    assert metrics["rca_top1_accuracy_pct"] == 100.0
    assert metrics["rca_top3_accuracy_pct"] == 100.0
    assert metrics["hallucinated_evidence_rate_pct"] == 0.0
    assert metrics["unsafe_action_rejection_rate_pct"] == 100.0
    assert metrics["rollback_success_rate_pct"] == 100.0
    assert metrics["rca_latency_p95_ms"] < 50.0
