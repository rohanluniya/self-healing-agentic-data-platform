package sre.remediation

import rego.v1

# Allowlisted typed remediation tools ONLY.
allowlisted_tools := {
  "bounded_retry_task",
  "backfill_partition",
  "pause_broken_pipeline",
  "rollback_config_version",
  "rebuild_materialized_view",
}

# Explicitly forbidden destructive or arbitrary execution operations.
forbidden_tools := {
  "drop_table",
  "delete_prod_data",
  "truncate_table",
  "shell_exec",
  "alter_permissions",
  "unbounded_backfill",
}

# Default deny for safety.
default allow := false
default requires_approval := true

# Collect all policy violation reasons deterministically.
violations contains msg if {
  input.tool_name in forbidden_tools
  msg := sprintf("forbidden_destructive_tool:%s", [input.tool_name])
}

violations contains msg if {
  not (input.tool_name in allowlisted_tools)
  not (input.tool_name in forbidden_tools)
  msg := sprintf("unlisted_tool:%s", [input.tool_name])
}

violations contains "false_positive_incident_cannot_mutate" if {
  input.incident_is_false_positive == true
}

violations contains "read_only_mode_blocks_execution" if {
  input.phase == "execute"
  input.agent_mode == "read_only"
}

violations contains "viewer_role_cannot_mutate" if {
  input.actor_role == "viewer"
}

violations contains "operator_role_required_for_dry_run_or_execute" if {
  input.phase in {"dry_run", "execute", "rollback"}
  not (input.actor_role in {"operator", "admin"})
}

violations contains "approver_role_required_for_approval" if {
  input.phase == "approve"
  not (input.actor_role in {"approver", "admin"})
}

violations contains "missing_idempotency_key" if {
  input.phase == "execute"
  trim_space(object.get(input, "idempotency_key", "")) == ""
}

violations contains "dry_run_required_before_execute" if {
  input.phase == "execute"
  not input.dry_run_completed
}

violations contains "preconditions_not_satisfied" if {
  input.phase == "execute"
  not input.preconditions_passed
}

violations contains "human_approval_required" if {
  input.phase == "execute"
  requires_approval
  not input.approved
}

violations contains "separation_of_duties_violation" if {
  input.phase == "execute"
  input.enforce_sod == true
  input.approved == true
  object.get(input, "approver_id", "") == object.get(input, "operator_id", "")
}

violations contains "evidence_grounding_failed" if {
  object.get(input, "verified_evidence_count", 0) < 1
}

# Tool-specific parameter guardrails.
violations contains "retry_limit_exceeded" if {
  input.tool_name == "bounded_retry_task"
  max_r := object.get(input.parameters, "max_retries", 0)
  max_r < 1
}

violations contains "retry_limit_exceeded" if {
  input.tool_name == "bounded_retry_task"
  max_r := object.get(input.parameters, "max_retries", 0)
  max_r > 3
}

violations contains "backfill_partition_limit_exceeded" if {
  input.tool_name == "backfill_partition"
  cnt := object.get(input.parameters, "partition_count", 0)
  cnt < 1
}

violations contains "backfill_partition_limit_exceeded" if {
  input.tool_name == "backfill_partition"
  cnt := object.get(input.parameters, "partition_count", 0)
  cnt > 24
}

violations contains "timeout_exceeded" if {
  timeout := object.get(input.parameters, "timeout_seconds", 60)
  timeout > 900
}

violations contains "invalid_rollback_target_version" if {
  input.tool_name == "rollback_config_version"
  target := object.get(input.parameters, "target_version", "")
  expected := object.get(input, "last_known_good_version", "")
  target != expected
}

violations contains "rollback_target_matches_current_version" if {
  input.tool_name == "rollback_config_version"
  target := object.get(input.parameters, "target_version", "")
  current := object.get(input, "current_config_version", "")
  target == current
}

violations contains "rebuild_mv_requires_gold_layer" if {
  input.tool_name == "rebuild_materialized_view"
  object.get(input, "asset_layer", "") != "gold"
}

allow if {
  count(violations) == 0
}

risk_level := "forbidden" if {
  input.tool_name in forbidden_tools
} else := "high" if {
  input.asset_tier == "tier0"
} else := "medium" if {
  input.tool_name in {"rollback_config_version", "backfill_partition", "pause_broken_pipeline"}
} else := "low"

decision := {
  "allow": allow,
  "requires_approval": requires_approval,
  "risk_level": risk_level,
  "violations": sort([v | some v in violations]),
  "policy_version": "sre.remediation/v1.0.0",
}
