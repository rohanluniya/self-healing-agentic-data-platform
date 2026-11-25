"""Policy-Constrained Agentic Remediation Engine with Dry-Run, Approval, Idempotency, Post-Checks, Auto-Rollback & Audit Chain."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from agentic_sre.config import Settings
from agentic_sre.lakehouse import IcebergEvidenceLakehouse
from agentic_sre.logging_utils import get_logger
from agentic_sre.opa_policy import ALLOWLISTED_TOOLS, OpaPolicyEngine
from agentic_sre.platform_model import PlatformStateStore
from agentic_sre.telemetry import DEFAULT_TELEMETRY, TelemetryHub
from models.schemas import (
    AuditLogEntryModel,
    PolicyDecisionModel,
    RemediationPlanModel,
)


class RemediationError(ValueError):
    """Domain error raised when a remediation transition violates policy or lifecycle constraints."""

    def __init__(self, message: str, status_code: int = 400, policy_decision: PolicyDecisionModel | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.policy_decision = policy_decision


class RemediationEngine:
    """Executes only OPA-approved, dry-run-verified, human-approved, idempotent, reversible remediations."""

    def __init__(
        self,
        settings: Settings,
        lakehouse: IcebergEvidenceLakehouse,
        state_store: PlatformStateStore,
        policy_engine: OpaPolicyEngine | None = None,
        telemetry: TelemetryHub | None = None,
    ) -> None:
        self.settings = settings
        self.lakehouse = lakehouse
        self.state_store = state_store
        self.policy = policy_engine or OpaPolicyEngine(
            opa_policy_url=settings.opa_policy_url, telemetry=telemetry
        )
        self.telemetry = telemetry or DEFAULT_TELEMETRY
        self.logger = get_logger("agentic_sre.remediation", settings.logs_dir / "control_plane.jsonl")

    # ------------------------------------------------------------------
    # Immutable SHA-256 hash-chained audit trail persisted in Iceberg V2
    # ------------------------------------------------------------------
    def _append_audit(
        self,
        *,
        event_type: str,
        actor_id: str,
        actor_role: str,
        outcome: str,
        details: dict[str, Any],
        plan_id: str | None = None,
        incident_id: str | None = None,
        tool_name: str | None = None,
        target_asset_id: str | None = None,
    ) -> AuditLogEntryModel:
        existing = sorted(
            self.lakehouse.read_rows("gold.remediation_audit_log"),
            key=lambda r: int(r.get("seq_no") or 0),
        )
        prev_hash = str(existing[-1]["entry_hash"]) if existing else "GENESIS_0000000000000000"
        next_seq = int(existing[-1].get("seq_no") or 0) + 1 if existing else 1
        ts = datetime.now(UTC).isoformat()
        audit_id = f"aud-{uuid.uuid4().hex[:12]}"
        details_json = json.dumps(details, sort_keys=True)
        canonical = f"{audit_id}|{next_seq}|{ts}|{event_type}|{plan_id}|{incident_id}|{actor_id}|{outcome}|{details_json}|{prev_hash}"
        entry_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        entry = AuditLogEntryModel(
            audit_id=audit_id,
            seq_no=next_seq,
            timestamp=ts,
            event_type=event_type,
            plan_id=plan_id,
            incident_id=incident_id,
            actor_id=actor_id,
            actor_role=actor_role,
            tool_name=tool_name,
            target_asset_id=target_asset_id,
            outcome=outcome,
            details_json=details_json,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )
        self.lakehouse.append("gold.remediation_audit_log", [entry.model_dump()])
        self.logger.info(
            f"audit:{event_type} outcome={outcome} plan={plan_id} tool={tool_name}",
            extra={
                "correlation_id": incident_id,
                "run_id": plan_id,
                "component": "remediation_engine",
                "extra_fields": {"actor_id": actor_id, "actor_role": actor_role, "outcome": outcome},
            },
        )
        return entry

    # ------------------------------------------------------------------
    # Plan persistence helpers (Iceberg V2 gold.remediation_plans)
    # ------------------------------------------------------------------
    def list_plans(self) -> list[RemediationPlanModel]:
        rows = self.lakehouse.read_rows("gold.remediation_plans")
        return [self._row_to_plan(r) for r in rows]

    def get_plan(self, plan_id: str) -> RemediationPlanModel:
        for plan in self.list_plans():
            if plan.plan_id == plan_id:
                return plan
        raise RemediationError(f"Remediation plan not found: {plan_id}", status_code=404)

    def _upsert_plan(self, plan: RemediationPlanModel) -> None:
        rows = self.lakehouse.read_rows("gold.remediation_plans")
        serialized = self._plan_to_row(plan)
        replaced = False
        for i, row in enumerate(rows):
            if row["plan_id"] == plan.plan_id:
                rows[i] = serialized
                replaced = True
                break
        if not replaced:
            rows.append(serialized)
        self.lakehouse.overwrite("gold.remediation_plans", rows)

    @staticmethod
    def _plan_to_row(plan: RemediationPlanModel) -> dict[str, Any]:
        return {
            "plan_id": plan.plan_id,
            "incident_id": plan.incident_id,
            "tool_name": plan.tool_name,
            "target_asset_id": plan.target_asset_id,
            "parameters_json": json.dumps(plan.parameters, sort_keys=True),
            "idempotency_key": plan.idempotency_key,
            "status": plan.status,
            "dry_run_preview": plan.dry_run_preview,
            "preconditions_passed": plan.preconditions_passed,
            "precondition_details_json": json.dumps(plan.precondition_details),
            "policy_decision_json": plan.policy_decision.model_dump_json(),
            "proposed_by": plan.proposed_by,
            "approved_by": plan.approved_by,
            "approved_at": plan.approved_at,
            "executed_at": plan.executed_at,
            "execution_count": plan.execution_count,
            "post_check_passed": plan.post_check_passed,
            "post_check_details": plan.post_check_details,
            "rollback_performed": plan.rollback_performed,
            "pre_action_snapshot_json": json.dumps(plan.pre_action_snapshot, sort_keys=True),
            "post_action_snapshot_json": json.dumps(plan.post_action_snapshot, sort_keys=True),
        }

    @staticmethod
    def _row_to_plan(row: dict[str, Any]) -> RemediationPlanModel:
        return RemediationPlanModel(
            plan_id=str(row["plan_id"]),
            incident_id=str(row["incident_id"]),
            tool_name=str(row["tool_name"]),
            target_asset_id=str(row["target_asset_id"]),
            parameters=json.loads(row.get("parameters_json") or "{}"),
            idempotency_key=str(row["idempotency_key"]),
            status=str(row["status"]),
            dry_run_preview=str(row.get("dry_run_preview") or ""),
            preconditions_passed=bool(row.get("preconditions_passed", False)),
            precondition_details=json.loads(row.get("precondition_details_json") or "[]"),
            policy_decision=PolicyDecisionModel(**json.loads(row["policy_decision_json"])),
            proposed_by=str(row["proposed_by"]),
            approved_by=row.get("approved_by"),
            approved_at=row.get("approved_at"),
            executed_at=row.get("executed_at"),
            execution_count=int(row.get("execution_count") or 0),
            post_check_passed=row.get("post_check_passed"),
            post_check_details=row.get("post_check_details"),
            rollback_performed=bool(row.get("rollback_performed", False)),
            pre_action_snapshot=json.loads(row.get("pre_action_snapshot_json") or "{}"),
            post_action_snapshot=json.loads(row.get("post_action_snapshot_json") or "{}"),
        )

    def _load_incident_row(self, incident_id: str) -> dict[str, Any]:
        for row in self.lakehouse.read_rows("silver.correlated_incidents"):
            if row["incident_id"] == incident_id:
                return row
        raise RemediationError(f"Incident not found: {incident_id}", status_code=404)

    def _verified_evidence_count(self, incident_id: str) -> int:
        hyps = [
            h
            for h in self.lakehouse.read_rows("gold.rca_hypotheses")
            if h["incident_id"] == incident_id
        ]
        if not hyps:
            return 0
        hyps.sort(key=lambda h: int(h["rank"]))
        return int(hyps[0].get("verified_citation_count") or 0)

    def _evaluate_preconditions(
        self,
        tool_name: str,
        asset: dict[str, Any],
        parameters: dict[str, Any],
    ) -> tuple[bool, list[str], str]:
        """Run strict precondition verification and build a deterministic dry-run preview."""
        checks: list[str] = []
        passed = True
        asset_id = asset["asset_id"]

        if tool_name not in ALLOWLISTED_TOOLS:
            return False, [f"Tool '{tool_name}' is not in the typed allowlist"], f"BLOCKED DRY-RUN: '{tool_name}' is forbidden/unlisted."

        if tool_name == "rollback_config_version":
            target_ver = str(parameters.get("target_version", ""))
            lkg = str(asset["last_known_good_version"])
            cur = str(asset["current_config_version"])
            ok_ver = bool(target_ver and target_ver == lkg and target_ver != cur)
            checks.append(f"last_known_good_version_match: {target_ver} == {lkg} (current={cur}) -> {'PASS' if ok_ver else 'FAIL'}")
            passed = passed and ok_ver
            preview = (
                f"[DRY-RUN] rollback_config_version on {asset_id}: "
                f"config {cur} -> {target_ver}; restore healthy transform state; reversible snapshot captured."
            )

        elif tool_name == "bounded_retry_task":
            max_r = int(parameters.get("max_retries", 0))
            ok_r = 1 <= max_r <= 3 and bool(asset.get("dag_id"))
            checks.append(f"bounded_retry_range_1_to_3_and_dag_exists: max_retries={max_r}, dag={asset.get('dag_id')} -> {'PASS' if ok_r else 'FAIL'}")
            passed = passed and ok_r
            preview = (
                f"[DRY-RUN] bounded_retry_task on {asset_id} (dag={asset.get('dag_id')}): "
                f"schedule up to {max_r} bounded retries with exponential backoff."
            )

        elif tool_name == "backfill_partition":
            cnt = int(parameters.get("partition_count", 0))
            part_key = str(parameters.get("partition_key", "dt=2026-11-24/hr=14"))
            ok_p = 1 <= cnt <= 24 and bool(part_key)
            checks.append(f"bounded_partition_backfill_1_to_24: count={cnt}, key={part_key} -> {'PASS' if ok_p else 'FAIL'}")
            passed = passed and ok_p
            preview = (
                f"[DRY-RUN] backfill_partition on {asset_id}: idempotent overwrite for {cnt} partition(s) [{part_key}]."
            )

        elif tool_name == "pause_broken_pipeline":
            reason = str(parameters.get("reason", "")).strip()
            ok_pause = bool(reason) and bool(asset.get("dag_id") or asset["layer"] in {"bronze", "silver"})
            checks.append(f"pause_reason_and_pipeline_target: reason_present={bool(reason)}, layer={asset['layer']} -> {'PASS' if ok_pause else 'FAIL'}")
            passed = passed and ok_pause
            preview = (
                f"[DRY-RUN] pause_broken_pipeline on {asset_id} (dag={asset.get('dag_id')}): "
                f"pause downstream ingestion schedule to isolate fault ({reason})."
            )

        elif tool_name == "rebuild_materialized_view":
            ok_mv = asset["layer"] == "gold"
            checks.append(f"gold_materialized_view_layer_check: layer={asset['layer']} -> {'PASS' if ok_mv else 'FAIL'}")
            passed = passed and ok_mv
            preview = (
                f"[DRY-RUN] rebuild_materialized_view on {asset_id}: atomic Iceberg snapshot refresh "
                f"restoring SLA freshness <= {asset['sla_freshness_minutes']}m."
            )
        else:
            passed = False
            preview = f"[DRY-RUN] Unsupported tool {tool_name}"

        return passed, checks, preview

    # ------------------------------------------------------------------
    # Step 1: Dry-Run Preview + OPA Policy Gate
    # ------------------------------------------------------------------
    def propose_dry_run(
        self,
        *,
        incident_id: str,
        tool_name: str,
        target_asset_id: str,
        parameters: dict[str, Any],
        actor_id: str,
        actor_role: str,
        idempotency_key: str | None = None,
    ) -> RemediationPlanModel:
        with self.telemetry.start_span(
            "remediation.dry_run",
            {"incident_id": incident_id, "tool_name": tool_name, "target_asset_id": target_asset_id},
        ):
            inc = self._load_incident_row(incident_id)
            try:
                asset = self.state_store.get(target_asset_id)
            except KeyError as exc:
                raise RemediationError(str(exc), status_code=404) from exc

            verified_ev = self._verified_evidence_count(incident_id)
            pre_passed, pre_details, preview = self._evaluate_preconditions(tool_name, asset, parameters)
            idem = idempotency_key or f"idem-{hashlib.sha256(f'{incident_id}:{tool_name}:{target_asset_id}:{json.dumps(parameters, sort_keys=True)}'.encode()).hexdigest()[:16]}"

            policy_input = {
                "tool_name": tool_name,
                "phase": "dry_run",
                "agent_mode": self.settings.agent_mode,
                "actor_role": actor_role,
                "operator_id": actor_id,
                "asset_tier": asset["tier"],
                "asset_layer": asset["layer"],
                "current_config_version": asset["current_config_version"],
                "last_known_good_version": asset["last_known_good_version"],
                "incident_is_false_positive": bool(inc.get("is_false_positive", False)),
                "verified_evidence_count": verified_ev,
                "parameters": parameters,
            }
            decision = self.policy.evaluate(policy_input)
            plan_id = f"plan-{uuid.uuid4().hex[:10]}"

            status = "AWAITING_APPROVAL" if (decision.allow and pre_passed) else "POLICY_DENIED"
            plan = RemediationPlanModel(
                plan_id=plan_id,
                incident_id=incident_id,
                tool_name=tool_name,
                target_asset_id=target_asset_id,
                parameters=parameters,
                idempotency_key=idem,
                status=status,
                dry_run_preview=preview,
                preconditions_passed=pre_passed,
                precondition_details=pre_details,
                policy_decision=decision,
                proposed_by=actor_id,
                pre_action_snapshot=asset,
            )
            self._upsert_plan(plan)
            self._append_audit(
                event_type="DRY_RUN_PROPOSED" if decision.allow else "POLICY_DENIED",
                actor_id=actor_id,
                actor_role=actor_role,
                plan_id=plan_id,
                incident_id=incident_id,
                tool_name=tool_name,
                target_asset_id=target_asset_id,
                outcome=status,
                details={
                    "violations": decision.violations,
                    "preconditions_passed": pre_passed,
                    "idempotency_key": idem,
                    "preview": preview,
                },
            )
            if not decision.allow:
                raise RemediationError(
                    f"OPA policy denied remediation '{tool_name}': {', '.join(decision.violations)}",
                    status_code=403,
                    policy_decision=decision,
                )
            return plan

    # ------------------------------------------------------------------
    # Step 2: Human Approval Gate (Separation of Duties)
    # ------------------------------------------------------------------
    def approve_plan(
        self,
        *,
        plan_id: str,
        approver_id: str,
        approver_role: str,
        comment: str = "",
    ) -> RemediationPlanModel:
        with self.telemetry.start_span("remediation.approve", {"plan_id": plan_id}):
            plan = self.get_plan(plan_id)
            inc = self._load_incident_row(plan.incident_id)
            asset = self.state_store.get(plan.target_asset_id)

            decision = self.policy.evaluate(
                {
                    "tool_name": plan.tool_name,
                    "phase": "approve",
                    "agent_mode": self.settings.agent_mode,
                    "actor_role": approver_role,
                    "operator_id": plan.proposed_by,
                    "approver_id": approver_id,
                    "asset_tier": asset["tier"],
                    "asset_layer": asset["layer"],
                    "current_config_version": asset["current_config_version"],
                    "last_known_good_version": asset["last_known_good_version"],
                    "incident_is_false_positive": bool(inc.get("is_false_positive", False)),
                    "verified_evidence_count": self._verified_evidence_count(plan.incident_id),
                    "parameters": plan.parameters,
                }
            )
            if not decision.allow:
                self._append_audit(
                    event_type="APPROVAL_DENIED",
                    actor_id=approver_id,
                    actor_role=approver_role,
                    plan_id=plan_id,
                    incident_id=plan.incident_id,
                    tool_name=plan.tool_name,
                    target_asset_id=plan.target_asset_id,
                    outcome="DENIED",
                    details={"violations": decision.violations},
                )
                raise RemediationError(
                    f"Approval blocked by OPA policy: {', '.join(decision.violations)}",
                    status_code=403,
                    policy_decision=decision,
                )

            if plan.status not in {"AWAITING_APPROVAL", "APPROVED"}:
                raise RemediationError(f"Plan {plan_id} cannot be approved from state {plan.status}", status_code=409)

            if plan.status == "APPROVED":
                return plan

            updated = plan.model_copy(
                update={
                    "status": "APPROVED",
                    "approved_by": approver_id,
                    "approved_at": datetime.now(UTC).isoformat(),
                    "policy_decision": decision,
                }
            )
            self._upsert_plan(updated)
            self._append_audit(
                event_type="HUMAN_APPROVED",
                actor_id=approver_id,
                actor_role=approver_role,
                plan_id=plan_id,
                incident_id=plan.incident_id,
                tool_name=plan.tool_name,
                target_asset_id=plan.target_asset_id,
                outcome="APPROVED",
                details={"comment": comment, "proposed_by": plan.proposed_by},
            )
            return updated

    # ------------------------------------------------------------------
    # Step 3: Idempotent Execution + Post-Action Verification + Auto-Rollback
    # ------------------------------------------------------------------
    def execute_plan(
        self,
        *,
        plan_id: str,
        idempotency_key: str,
        operator_id: str,
        operator_role: str,
        agent_mode_override: str | None = None,
        simulate_post_check_failure: bool = False,
    ) -> tuple[RemediationPlanModel, bool]:
        """Execute an approved plan at most once per idempotency_key. Returns (plan, is_idempotent_replay)."""
        with self.telemetry.start_span(
            "remediation.execute",
            {"plan_id": plan_id, "idempotency_key": idempotency_key},
        ):
            # Strict global idempotency guard across all executed plans.
            for existing in self.list_plans():
                if existing.idempotency_key == idempotency_key and existing.execution_count >= 1:
                    self._append_audit(
                        event_type="IDEMPOTENT_REPLAY_GUARDED",
                        actor_id=operator_id,
                        actor_role=operator_role,
                        plan_id=existing.plan_id,
                        incident_id=existing.incident_id,
                        tool_name=existing.tool_name,
                        target_asset_id=existing.target_asset_id,
                        outcome="NOOP_ALREADY_EXECUTED",
                        details={"idempotency_key": idempotency_key, "execution_count": existing.execution_count},
                    )
                    return existing, True

            plan = self.get_plan(plan_id)
            if idempotency_key != plan.idempotency_key:
                raise RemediationError("idempotency_key mismatch for remediation plan", status_code=400)

            inc = self._load_incident_row(plan.incident_id)
            asset = self.state_store.get(plan.target_asset_id)
            effective_mode = agent_mode_override or self.settings.agent_mode

            decision = self.policy.evaluate(
                {
                    "tool_name": plan.tool_name,
                    "phase": "execute",
                    "agent_mode": effective_mode,
                    "actor_role": operator_role,
                    "operator_id": operator_id,
                    "approver_id": plan.approved_by or "",
                    "enforce_sod": self.settings.enforce_sod,
                    "approved": plan.status == "APPROVED" and bool(plan.approved_by),
                    "dry_run_completed": bool(plan.dry_run_preview),
                    "preconditions_passed": plan.preconditions_passed,
                    "idempotency_key": idempotency_key,
                    "asset_tier": asset["tier"],
                    "asset_layer": asset["layer"],
                    "current_config_version": asset["current_config_version"],
                    "last_known_good_version": asset["last_known_good_version"],
                    "incident_is_false_positive": bool(inc.get("is_false_positive", False)),
                    "verified_evidence_count": self._verified_evidence_count(plan.incident_id),
                    "parameters": plan.parameters,
                }
            )
            if not decision.allow:
                self._append_audit(
                    event_type="EXECUTION_POLICY_DENIED",
                    actor_id=operator_id,
                    actor_role=operator_role,
                    plan_id=plan_id,
                    incident_id=plan.incident_id,
                    tool_name=plan.tool_name,
                    target_asset_id=plan.target_asset_id,
                    outcome="POLICY_DENIED",
                    details={"violations": decision.violations, "agent_mode": effective_mode},
                )
                raise RemediationError(
                    f"OPA policy blocked execution: {', '.join(decision.violations)}",
                    status_code=403,
                    policy_decision=decision,
                )

            pre_snapshot = self.state_store.get(plan.target_asset_id)
            post_snapshot = self._apply_typed_tool(plan.tool_name, plan.target_asset_id, plan.parameters)

            # Post-action health verification
            post_ok, post_details = self._verify_post_action_health(
                plan.tool_name, post_snapshot, simulate_failure=simulate_post_check_failure
            )
            executed_at = datetime.now(UTC).isoformat()

            if post_ok:
                updated = plan.model_copy(
                    update={
                        "status": "COMPLETED",
                        "executed_at": executed_at,
                        "execution_count": plan.execution_count + 1,
                        "post_check_passed": True,
                        "post_check_details": post_details,
                        "rollback_performed": False,
                        "pre_action_snapshot": pre_snapshot,
                        "post_action_snapshot": post_snapshot,
                        "policy_decision": decision,
                    }
                )
                self._upsert_plan(updated)
                self._update_incident_status(plan.incident_id, "mitigated")
                self.telemetry.remediations_executed.labels(tool_name=plan.tool_name, outcome="completed").inc()
                self._append_audit(
                    event_type="EXECUTION_VERIFIED",
                    actor_id=operator_id,
                    actor_role=operator_role,
                    plan_id=plan_id,
                    incident_id=plan.incident_id,
                    tool_name=plan.tool_name,
                    target_asset_id=plan.target_asset_id,
                    outcome="COMPLETED",
                    details={"post_check": post_details, "idempotency_key": idempotency_key},
                )
                return updated, False

            # Post-action verification failed -> AUTOMATIC ROLLBACK!
            self._append_audit(
                event_type="POST_CHECK_FAILED",
                actor_id="system-verifier",
                actor_role="system",
                plan_id=plan_id,
                incident_id=plan.incident_id,
                tool_name=plan.tool_name,
                target_asset_id=plan.target_asset_id,
                outcome="TRIGGERING_AUTO_ROLLBACK",
                details={"post_check": post_details},
            )
            restored = self.state_store.update(plan.target_asset_id, pre_snapshot)
            rolled = plan.model_copy(
                update={
                    "status": "ROLLED_BACK",
                    "executed_at": executed_at,
                    "execution_count": plan.execution_count + 1,
                    "post_check_passed": False,
                    "post_check_details": f"{post_details}; automatic rollback restored pre-action snapshot.",
                    "rollback_performed": True,
                    "pre_action_snapshot": pre_snapshot,
                    "post_action_snapshot": restored,
                    "policy_decision": decision,
                }
            )
            self._upsert_plan(rolled)
            self._update_incident_status(plan.incident_id, "rolled_back")
            self.telemetry.remediations_executed.labels(tool_name=plan.tool_name, outcome="auto_rolled_back").inc()
            self.telemetry.rollbacks_triggered.labels(trigger="auto_post_check_failed").inc()
            self._append_audit(
                event_type="AUTO_ROLLBACK_COMPLETED",
                actor_id="system-verifier",
                actor_role="system",
                plan_id=plan_id,
                incident_id=plan.incident_id,
                tool_name=plan.tool_name,
                target_asset_id=plan.target_asset_id,
                outcome="ROLLED_BACK",
                details={"restored_config_version": restored["current_config_version"], "restored_status": restored["status"]},
            )
            return rolled, False

    def rollback_plan(
        self,
        *,
        plan_id: str,
        operator_id: str,
        operator_role: str,
        reason: str = "Manual operator rollback",
    ) -> RemediationPlanModel:
        """Manually restore pre-action snapshot for a completed remediation plan."""
        with self.telemetry.start_span("remediation.rollback", {"plan_id": plan_id}):
            if operator_role not in {"operator", "admin"}:
                raise RemediationError("Only operator role can trigger rollback", status_code=403)
            plan = self.get_plan(plan_id)
            if not plan.pre_action_snapshot:
                raise RemediationError(f"Plan {plan_id} has no pre-action snapshot to restore", status_code=400)
            restored = self.state_store.update(plan.target_asset_id, plan.pre_action_snapshot)
            updated = plan.model_copy(
                update={
                    "status": "ROLLED_BACK",
                    "rollback_performed": True,
                    "post_action_snapshot": restored,
                    "post_check_details": f"Manual rollback completed: {reason}",
                }
            )
            self._upsert_plan(updated)
            self._update_incident_status(plan.incident_id, "rolled_back")
            self.telemetry.rollbacks_triggered.labels(trigger="manual_operator").inc()
            self._append_audit(
                event_type="MANUAL_ROLLBACK_COMPLETED",
                actor_id=operator_id,
                actor_role=operator_role,
                plan_id=plan_id,
                incident_id=plan.incident_id,
                tool_name=plan.tool_name,
                target_asset_id=plan.target_asset_id,
                outcome="ROLLED_BACK",
                details={"reason": reason, "restored_config_version": restored["current_config_version"]},
            )
            return updated

    def _apply_typed_tool(
        self,
        tool_name: str,
        target_asset_id: str,
        parameters: dict[str, Any],
    ) -> dict[str, Any]:
        """Mutate real fixture platform operational state via strongly typed allowlisted operations."""
        asset = self.state_store.get(target_asset_id)
        if tool_name == "rollback_config_version":
            target_ver = str(parameters["target_version"])
            return self.state_store.update(
                target_asset_id,
                {
                    "current_config_version": target_ver,
                    "status": "healthy",
                    "freshness_lag_minutes": 3.0,
                },
            )
        if tool_name == "bounded_retry_task":
            retries = int(parameters["max_retries"])
            return self.state_store.update(
                target_asset_id,
                {
                    "retry_count": int(asset.get("retry_count", 0)) + retries,
                    "status": "healthy",
                    "freshness_lag_minutes": 2.5,
                },
            )
        if tool_name == "backfill_partition":
            part_key = str(parameters.get("partition_key", ""))
            remaining = [p for p in asset.get("missing_partitions", []) if p != part_key]
            return self.state_store.update(
                target_asset_id,
                {
                    "missing_partitions": remaining,
                    "status": "healthy",
                    "freshness_lag_minutes": 4.0,
                },
            )
        if tool_name == "pause_broken_pipeline":
            return self.state_store.update(
                target_asset_id,
                {
                    "pipeline_paused": True,
                    "status": "paused",
                    "cost_multiplier": 1.0,
                },
            )
        if tool_name == "rebuild_materialized_view":
            return self.state_store.update(
                target_asset_id,
                {
                    "status": "healthy",
                    "freshness_lag_minutes": 1.2,
                },
            )
        raise RemediationError(f"Tool '{tool_name}' is not allowlisted", status_code=403)

    @staticmethod
    def _verify_post_action_health(
        tool_name: str,
        post_snapshot: dict[str, Any],
        simulate_failure: bool = False,
    ) -> tuple[bool, str]:
        if simulate_failure:
            return False, "Post-action health probe detected lingering error rate > 5% and DQ drift"
        if tool_name == "pause_broken_pipeline":
            ok = bool(post_snapshot.get("pipeline_paused")) and post_snapshot.get("status") == "paused"
            return ok, "Pipeline safely isolated (paused=True, runaway cost stopped)" if ok else "Pipeline failed to enter paused state"
        if tool_name == "rebuild_materialized_view":
            lag = float(post_snapshot.get("freshness_lag_minutes", 999.0))
            sla = float(post_snapshot.get("sla_freshness_minutes", 15.0))
            ok = lag <= sla and post_snapshot.get("status") == "healthy"
            return ok, f"MV refreshed within SLA (freshness_lag={lag}m <= {sla}m)" if ok else f"MV still stale ({lag}m > {sla}m)"
        ok = post_snapshot.get("status") == "healthy"
        return ok, f"Post-check passed: status={post_snapshot.get('status')}, config={post_snapshot.get('current_config_version')}"

    def _update_incident_status(self, incident_id: str, new_status: str) -> None:
        rows = self.lakehouse.read_rows("silver.correlated_incidents")
        for row in rows:
            if row["incident_id"] == incident_id:
                row["status"] = new_status
        self.lakehouse.overwrite("silver.correlated_incidents", rows)

    def rebuild_platform_state_from_iceberg(self) -> dict[str, Any]:
        """Rebuild local operational state purely from durable Apache Iceberg V2 tables after state loss."""
        self.state_store.reset()
        signals = self.lakehouse.read_rows("bronze.telemetry_signals")
        self.state_store.apply_signal_effects(signals)
        plans = self.list_plans()
        replayed = 0
        for plan in plans:
            if plan.status == "COMPLETED" and not plan.rollback_performed and plan.post_action_snapshot:
                self.state_store.update(plan.target_asset_id, plan.post_action_snapshot)
                replayed += 1
        return {
            "rebuilt_from_iceberg": True,
            "signals_replayed": len(signals),
            "completed_plans_reapplied": replayed,
            "assets_restored": len(self.state_store.list_assets()),
        }
