"""OPA Rego Policy Evaluator (remote OPA REST client + deterministic embedded Rego-v1 parity engine)."""

from __future__ import annotations

from typing import Any

import requests

from agentic_sre.telemetry import DEFAULT_TELEMETRY, TelemetryHub
from models.schemas import PolicyDecisionModel

ALLOWLISTED_TOOLS: frozenset[str] = frozenset(
    {
        "bounded_retry_task",
        "backfill_partition",
        "pause_broken_pipeline",
        "rollback_config_version",
        "rebuild_materialized_view",
    }
)

FORBIDDEN_TOOLS: frozenset[str] = frozenset(
    {
        "drop_table",
        "delete_prod_data",
        "truncate_table",
        "shell_exec",
        "alter_permissions",
        "unbounded_backfill",
    }
)

POLICY_VERSION = "sre.remediation/v1.0.0"


class OpaPolicyEngine:
    """Evaluates remediation actions against infra/opa/remediation_policy.rego semantics."""

    def __init__(
        self,
        opa_policy_url: str = "",
        telemetry: TelemetryHub | None = None,
        timeout_seconds: float = 2.0,
    ) -> None:
        self.opa_policy_url = opa_policy_url.strip().rstrip("/")
        self.telemetry = telemetry or DEFAULT_TELEMETRY
        self.timeout_seconds = timeout_seconds

    def evaluate(self, payload: dict[str, Any]) -> PolicyDecisionModel:
        """Evaluate policy via remote OPA server if configured & reachable, else deterministic embedded engine."""
        if self.opa_policy_url:
            remote = self._try_remote_opa(payload)
            if remote is not None:
                self._record_metric(remote, payload)
                return remote
        decision = self._evaluate_embedded(payload)
        self._record_metric(decision, payload)
        return decision

    def _try_remote_opa(self, payload: dict[str, Any]) -> PolicyDecisionModel | None:
        try:
            resp = requests.post(
                f"{self.opa_policy_url}/v1/data/sre/remediation/decision",
                json={"input": payload},
                timeout=self.timeout_seconds,
            )
            resp.raise_for_status()
            res = resp.json().get("result")
            if isinstance(res, dict) and "allow" in res:
                return PolicyDecisionModel(
                    allow=bool(res["allow"]),
                    requires_approval=bool(res.get("requires_approval", True)),
                    risk_level=str(res.get("risk_level", "high")),
                    violations=list(res.get("violations", [])),
                    policy_version=str(res.get("policy_version", POLICY_VERSION)),
                    engine="remote_opa_server",
                )
        except Exception:
            return None
        return None

    def _evaluate_embedded(self, inp: dict[str, Any]) -> PolicyDecisionModel:
        """Mirror every rule of infra/opa/remediation_policy.rego deterministically."""
        tool_name = str(inp.get("tool_name", "")).strip()
        phase = str(inp.get("phase", "dry_run")).strip()
        agent_mode = str(inp.get("agent_mode", "read_only")).strip()
        actor_role = str(inp.get("actor_role", "viewer")).strip()
        operator_id = str(inp.get("operator_id", "")).strip()
        approver_id = str(inp.get("approver_id", "")).strip()
        enforce_sod = bool(inp.get("enforce_sod", True))
        approved = bool(inp.get("approved", False))
        dry_run_completed = bool(inp.get("dry_run_completed", False))
        preconditions_passed = bool(inp.get("preconditions_passed", False))
        idempotency_key = str(inp.get("idempotency_key", "")).strip()
        asset_tier = str(inp.get("asset_tier", "tier0")).strip()
        asset_layer = str(inp.get("asset_layer", "")).strip()
        current_ver = str(inp.get("current_config_version", "")).strip()
        lkg_ver = str(inp.get("last_known_good_version", "")).strip()
        is_fp = bool(inp.get("incident_is_false_positive", False))
        verified_ev = int(inp.get("verified_evidence_count", 0))
        params = inp.get("parameters") or {}

        violations: set[str] = set()
        requires_approval = True

        if tool_name in FORBIDDEN_TOOLS:
            violations.add(f"forbidden_destructive_tool:{tool_name}")
        elif tool_name not in ALLOWLISTED_TOOLS:
            violations.add(f"unlisted_tool:{tool_name}")

        if is_fp:
            violations.add("false_positive_incident_cannot_mutate")

        if phase == "execute" and agent_mode == "read_only":
            violations.add("read_only_mode_blocks_execution")

        if actor_role == "viewer":
            violations.add("viewer_role_cannot_mutate")

        if phase in {"dry_run", "execute", "rollback"} and actor_role not in {"operator", "admin"}:
            violations.add("operator_role_required_for_dry_run_or_execute")

        if phase == "approve" and actor_role not in {"approver", "admin"}:
            violations.add("approver_role_required_for_approval")

        if phase == "execute" and not idempotency_key:
            violations.add("missing_idempotency_key")

        if phase == "execute" and not dry_run_completed:
            violations.add("dry_run_required_before_execute")

        if phase == "execute" and not preconditions_passed:
            violations.add("preconditions_not_satisfied")

        if phase == "execute" and requires_approval and not approved:
            violations.add("human_approval_required")

        if phase == "execute" and enforce_sod and approved and approver_id and operator_id and approver_id == operator_id:
            violations.add("separation_of_duties_violation")

        if verified_ev < 1:
            violations.add("evidence_grounding_failed")

        # Tool-specific bounded parameter guardrails.
        timeout = params.get("timeout_seconds", 60)
        try:
            timeout_val = float(timeout)
        except (TypeError, ValueError):
            timeout_val = 9999.0
        if timeout_val > 900 or timeout_val <= 0:
            violations.add("timeout_exceeded")

        if tool_name == "bounded_retry_task":
            max_r = params.get("max_retries", 0)
            if not isinstance(max_r, (int, float)) or max_r < 1 or max_r > 3:
                violations.add("retry_limit_exceeded")

        if tool_name == "backfill_partition":
            cnt = params.get("partition_count", 0)
            if not isinstance(cnt, (int, float)) or cnt < 1 or cnt > 24:
                violations.add("backfill_partition_limit_exceeded")

        if tool_name == "rollback_config_version":
            target = str(params.get("target_version", "")).strip()
            if not target or (lkg_ver and target != lkg_ver):
                violations.add("invalid_rollback_target_version")
            if current_ver and target == current_ver:
                violations.add("rollback_target_matches_current_version")

        if tool_name == "rebuild_materialized_view" and asset_layer and asset_layer != "gold":
            violations.add("rebuild_mv_requires_gold_layer")

        if tool_name in FORBIDDEN_TOOLS:
            risk_level = "forbidden"
        elif asset_tier == "tier0":
            risk_level = "high"
        elif tool_name in {"rollback_config_version", "backfill_partition", "pause_broken_pipeline"}:
            risk_level = "medium"
        else:
            risk_level = "low"

        return PolicyDecisionModel(
            allow=(len(violations) == 0),
            requires_approval=requires_approval,
            risk_level=risk_level,
            violations=sorted(violations),
            policy_version=POLICY_VERSION,
            engine="embedded_rego_v1",
        )

    def _record_metric(self, decision: PolicyDecisionModel, payload: dict[str, Any]) -> None:
        self.telemetry.policy_decisions.labels(
            decision="allow" if decision.allow else "deny",
            tool_name=str(payload.get("tool_name", "unknown")),
            phase=str(payload.get("phase", "unknown")),
        ).inc()
