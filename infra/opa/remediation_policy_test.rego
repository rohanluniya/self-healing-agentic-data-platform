package sre.remediation_test

import data.sre.remediation
import rego.v1

test_deny_drop_table if {
  res := remediation.decision with input as {
    "tool_name": "drop_table",
    "phase": "dry_run",
    "agent_mode": "guarded_active",
    "actor_role": "operator",
    "asset_tier": "tier0",
    "asset_layer": "gold",
    "incident_is_false_positive": false,
    "verified_evidence_count": 3,
    "parameters": {},
  }
  not res.allow
  res.risk_level == "forbidden"
}

test_deny_false_positive_mutation if {
  res := remediation.decision with input as {
    "tool_name": "bounded_retry_task",
    "phase": "dry_run",
    "agent_mode": "guarded_active",
    "actor_role": "operator",
    "asset_tier": "tier1",
    "asset_layer": "bronze",
    "incident_is_false_positive": true,
    "verified_evidence_count": 1,
    "parameters": {"max_retries": 2, "timeout_seconds": 120},
  }
  not res.allow
  "false_positive_incident_cannot_mutate" in res.violations
}

test_deny_unbounded_backfill if {
  res := remediation.decision with input as {
    "tool_name": "backfill_partition",
    "phase": "dry_run",
    "agent_mode": "guarded_active",
    "actor_role": "operator",
    "asset_tier": "tier1",
    "asset_layer": "silver",
    "incident_is_false_positive": false,
    "verified_evidence_count": 2,
    "parameters": {"partition_count": 120, "timeout_seconds": 300},
  }
  not res.allow
  "backfill_partition_limit_exceeded" in res.violations
}

test_deny_execute_in_read_only_mode if {
  res := remediation.decision with input as {
    "tool_name": "rollback_config_version",
    "phase": "execute",
    "agent_mode": "read_only",
    "actor_role": "operator",
    "operator_id": "op-1",
    "approver_id": "appr-1",
    "enforce_sod": true,
    "approved": true,
    "dry_run_completed": true,
    "preconditions_passed": true,
    "idempotency_key": "idem-001",
    "asset_tier": "tier0",
    "asset_layer": "silver",
    "current_config_version": "v2.14.0",
    "last_known_good_version": "v2.13.4",
    "incident_is_false_positive": false,
    "verified_evidence_count": 4,
    "parameters": {"target_version": "v2.13.4", "timeout_seconds": 180},
  }
  not res.allow
  "read_only_mode_blocks_execution" in res.violations
}

test_allow_approved_bounded_rollback if {
  res := remediation.decision with input as {
    "tool_name": "rollback_config_version",
    "phase": "execute",
    "agent_mode": "guarded_active",
    "actor_role": "operator",
    "operator_id": "op-1",
    "approver_id": "appr-1",
    "enforce_sod": true,
    "approved": true,
    "dry_run_completed": true,
    "preconditions_passed": true,
    "idempotency_key": "idem-002",
    "asset_tier": "tier0",
    "asset_layer": "silver",
    "current_config_version": "v2.14.0",
    "last_known_good_version": "v2.13.4",
    "incident_is_false_positive": false,
    "verified_evidence_count": 4,
    "parameters": {"target_version": "v2.13.4", "timeout_seconds": 180},
  }
  res.allow
  count(res.violations) == 0
}
