# ADR-003: OPA Rego v1 Policy Guardrails and Typed Allowlisted Tools

## Status
Accepted

## Context
Granting an operations agent arbitrary SQL, shell, or cloud-CLI execution creates catastrophic blast-radius risks (accidental `DROP TABLE`, unbounded backfills causing cloud billing spikes, or mutating state on false-positive noise).

## Decision
- Expose remediation capabilities exclusively through **five strongly typed, allowlisted tools**: `bounded_retry_task`, `backfill_partition`, `pause_broken_pipeline`, `rollback_config_version`, and `rebuild_materialized_view`.
- Encode all safety invariants in **OPA Rego v1** (`infra/opa/remediation_policy.rego` + `infra/opa/remediation_policy_test.rego`): default deny, read-only default mode, explicit forbidden tool list (`drop_table`, `delete_prod_data`, `truncate_table`, `shell_exec`, `alter_permissions`), hard bounds (`max_retries <= 3`, `partition_count <= 24`, `timeout_seconds <= 900`), non-mutation on suppressed false positives, and separation of duties (`operator_id != approver_id`).
- Support live remote OPA evaluation (`OPA_POLICY_URL`) in distributed deployments while providing an embedded deterministic Rego-v1 parity evaluator (`agentic_sre/opa_policy.py`) so local environments without the `opa` binary enforce identical rules.

## Consequences
- **Benefits:** 100% deterministic rejection of unsafe or unbounded operations, policy-as-code version control, and standalone native testability.
- **Tradeoffs:** Any change to `infra/opa/remediation_policy.rego` must be kept synchronized with `agentic_sre/opa_policy.py` and verified by CI running both `opa test` (via `openpolicyagent/opa:1.22.3`) and `pytest`.
