"""Unit tests for cross-asset lineage correlation, false-positive suppression, zero-hallucination RCA, and redaction."""

from __future__ import annotations

import pytest

from agentic_sre.correlator import IncidentCorrelator
from agentic_sre.logging_utils import redact_sensitive
from agentic_sre.platform_model import PlatformLineageGraph, default_platform_assets
from agentic_sre.rca import (
    DeterministicRcaEngine,
    OptionalLocalLLMAdapter,
    verify_evidence_pointers,
)
from ingestion.signal_generator import ALL_SCENARIOS, generate_scenario_signals
from models.schemas import EvidencePointer

EXPECTED_ROOTS = {
    "schema_breakage": ("kafka.orders_events", False, "pause_broken_pipeline"),
    "stale_table_sla_breach": ("gold.daily_revenue_mv", False, "rebuild_materialized_view"),
    "transient_retry_storm": ("bronze.payments_raw", False, "bounded_retry_task"),
    "bad_config_deployment": ("silver.orders_enriched", False, "rollback_config_version"),
    "compute_cost_partition_skew": ("silver.user_sessions", False, "pause_broken_pipeline"),
    "late_arriving_data": ("bronze.clickstream_raw", False, "backfill_partition"),
    "missing_upstream_partition": ("bronze.orders_raw", False, "backfill_partition"),
    "upstream_broker_outage": ("kafka.payments_events", False, "pause_broken_pipeline"),
    "false_positive_noisy_alert": ("consumer.growth_attribution_api", True, "none_read_only"),
}


@pytest.mark.parametrize("scenario", ALL_SCENARIOS)
def test_all_nine_scenarios_correlate_to_exact_root_cause(scenario: str) -> None:
    lineage = PlatformLineageGraph()
    assets = default_platform_assets()
    correlator = IncidentCorrelator(lineage=lineage, assets_metadata=assets)
    rca = DeterministicRcaEngine(lineage=lineage, assets_metadata=assets)

    sigs = generate_scenario_signals(scenario, seed=42)
    incidents, sig_map = correlator.correlate(sigs)
    assert len(incidents) == 1

    inc = incidents[0]
    exp_root, exp_fp, exp_tool = EXPECTED_ROOTS[scenario]
    assert inc.root_asset_id == exp_root
    assert inc.is_false_positive is exp_fp
    assert inc.recommended_tool == exp_tool

    sig_ids = {s["signal_id"] for s in sigs}
    span_ids = {s["span_id"] for s in sigs}
    edge_ids = {e.edge_id for e in lineage.edges}
    commits = {s["commit_version"] for s in sigs if s.get("commit_version")}

    hyps = rca.diagnose_incident(inc, sig_map[inc.incident_id], sig_ids, span_ids, edge_ids, commits)
    assert len(hyps) >= 1
    assert hyps[0].root_asset_id == exp_root
    assert hyps[0].hallucinated_citation_count == 0
    assert hyps[0].verified_citation_count == hyps[0].total_citation_count
    assert hyps[0].verified_citation_count >= 1


def test_deterministic_seed_produces_identical_ids() -> None:
    a = generate_scenario_signals("bad_config_deployment", seed=99)
    b = generate_scenario_signals("bad_config_deployment", seed=99)
    assert [x["signal_id"] for x in a] == [x["signal_id"] for x in b]
    assert [x["span_id"] for x in a] == [x["span_id"] for x in b]


def test_evidence_verifier_catches_fabricated_hallucinated_citation() -> None:
    pointers = [
        EvidencePointer(pointer_type="signal_id", pointer_id="sig-real-001", asset_id="silver.orders_enriched", summary="real"),
        EvidencePointer(pointer_type="signal_id", pointer_id="sig-fabricated-999", asset_id="silver.orders_enriched", summary="hallucinated"),
        EvidencePointer(pointer_type="commit_version", pointer_id="v9.9.9-invented", asset_id="silver.orders_enriched", summary="invented"),
    ]
    checked, verified, hallucinated = verify_evidence_pointers(
        pointers=pointers,
        persisted_signal_ids={"sig-real-001"},
        persisted_span_ids=set(),
        persisted_edge_ids=set(),
        persisted_commits={"v2.14.0"},
    )
    assert verified == 1
    assert hallucinated == 2
    assert checked[0].verified is True
    assert checked[1].verified is False
    assert checked[2].verified is False


def test_optional_local_llm_adapter_disabled_by_default() -> None:
    adapter = OptionalLocalLLMAdapter(enabled=False)
    correlator = IncidentCorrelator(assets_metadata=default_platform_assets())
    sigs = generate_scenario_signals("stale_table_sla_breach", seed=7)
    incs, _ = correlator.correlate(sigs)
    assert adapter.summarize_verified_bundle(incs[0], []) is None


def test_structured_log_redaction_strips_secrets() -> None:
    raw = "Auth failed for api_key=supersecret123 Bearer eyJhbGciOi token=abc dev-operator-key-ops user@example.com"
    cleaned = redact_sensitive(raw)
    assert "supersecret123" not in cleaned
    assert "eyJhbGciOi" not in cleaned
    assert "dev-operator-key-ops" not in cleaned
    assert "user@example.com" not in cleaned
