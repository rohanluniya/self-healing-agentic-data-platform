"""Pydantic v2 domain models for the Agentic SRE Control Plane."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class AssetNodeModel(BaseModel):
    asset_id: str
    layer: str
    owner_team: str
    tier: str
    dag_id: str | None = None
    spark_job: str | None = None
    sla_freshness_minutes: int
    current_config_version: str
    last_known_good_version: str
    schema_version: int
    status: str = "healthy"
    freshness_lag_minutes: float = 1.0


class LineageEdgeModel(BaseModel):
    edge_id: str
    source_asset_id: str
    target_asset_id: str
    job_name: str
    run_id: str


class EvidencePointer(BaseModel):
    pointer_type: str  # signal_id | span_id | commit_version | lineage_edge
    pointer_id: str
    asset_id: str
    summary: str
    verified: bool = False


class RcaHypothesisModel(BaseModel):
    hypothesis_id: str
    incident_id: str
    rank: int
    root_asset_id: str
    root_cause_category: str
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str
    recommended_tool: str
    recommended_parameters: dict[str, Any] = Field(default_factory=dict)
    evidence_pointers: list[EvidencePointer] = Field(default_factory=list)
    verified_citation_count: int = 0
    total_citation_count: int = 0
    hallucinated_citation_count: int = 0


class CorrelatedIncidentModel(BaseModel):
    incident_id: str
    title: str
    scenario_type: str
    root_asset_id: str
    impacted_assets: list[str]
    raw_alert_count: int
    severity: str
    status: str  # open | suppressed_false_positive | mitigated | rolled_back
    is_false_positive: bool = False
    first_event_time_ms: int
    detected_at_ms: int
    signal_ids: list[str]
    span_ids: list[str]
    lineage_edges: list[str]
    commit_versions: list[str]
    storm_compression_ratio: float
    recommended_tool: str
    recommended_parameters: dict[str, Any] = Field(default_factory=dict)


class EvidenceBundleResponse(BaseModel):
    incident: CorrelatedIncidentModel
    hypotheses: list[RcaHypothesisModel]
    verified_evidence_count: int
    total_evidence_count: int
    hallucinated_evidence_rate: float
    signals: list[dict[str, Any]]
    lineage_subgraph: list[LineageEdgeModel]
    optional_llm_summary: str | None = None


class PolicyEvaluationRequest(BaseModel):
    tool_name: str
    phase: str = "dry_run"  # dry_run | approve | execute | rollback
    target_asset_id: str
    incident_id: str | None = None
    incident_is_false_positive: bool = False
    agent_mode: str = "read_only"
    actor_role: str = "operator"
    operator_id: str = "op-console"
    approver_id: str = ""
    approved: bool = False
    dry_run_completed: bool = False
    preconditions_passed: bool = False
    idempotency_key: str = ""
    verified_evidence_count: int = 1
    parameters: dict[str, Any] = Field(default_factory=dict)


class PolicyDecisionModel(BaseModel):
    allow: bool
    requires_approval: bool
    risk_level: str
    violations: list[str]
    policy_version: str
    engine: str = "embedded_rego_v1"


class DryRunRequest(BaseModel):
    incident_id: str
    tool_name: str
    target_asset_id: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str | None = None
    reason: str = "Evidence-backed remediation dry-run"


class ApprovalRequest(BaseModel):
    comment: str = "Verified evidence bundle and OPA policy guardrails"


class ExecuteRequest(BaseModel):
    idempotency_key: str
    agent_mode_override: str | None = None
    simulate_post_check_failure: bool = False


class RollbackRequest(BaseModel):
    reason: str = "Manual operator rollback requested"


class RemediationPlanModel(BaseModel):
    plan_id: str
    incident_id: str
    tool_name: str
    target_asset_id: str
    parameters: dict[str, Any]
    idempotency_key: str
    status: str
    dry_run_preview: str
    preconditions_passed: bool
    precondition_details: list[str]
    policy_decision: PolicyDecisionModel
    proposed_by: str
    approved_by: str | None = None
    approved_at: str | None = None
    executed_at: str | None = None
    execution_count: int = 0
    post_check_passed: bool | None = None
    post_check_details: str | None = None
    rollback_performed: bool = False
    pre_action_snapshot: dict[str, Any] = Field(default_factory=dict)
    post_action_snapshot: dict[str, Any] = Field(default_factory=dict)


class AuditLogEntryModel(BaseModel):
    audit_id: str
    seq_no: int = 1
    timestamp: str
    event_type: str
    plan_id: str | None = None
    incident_id: str | None = None
    actor_id: str
    actor_role: str
    tool_name: str | None = None
    target_asset_id: str | None = None
    outcome: str
    details_json: str
    prev_hash: str
    entry_hash: str


class ScenarioInjectRequest(BaseModel):
    scenario: str
    seed: int = 42
