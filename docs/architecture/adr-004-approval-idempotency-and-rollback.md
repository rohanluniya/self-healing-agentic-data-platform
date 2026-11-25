# ADR-004: Mandatory Dry-Run, Human Approval Gate, Idempotency Keys, and Automatic Rollback

## Status
Accepted

## Context
Even allowlisted remediation actions can cause unintended side effects if retried twice under network timeouts, executed without review on tier-0 assets, or applied when the underlying fault does not clear.

## Decision
Enforce a strict multi-stage remediation state machine for every mutating tool:
1. **Dry-Run Preview & Preconditions:** Compute exact operational diff and verify preconditions before approval.
2. **Human Approval Gate with Separation of Duties:** Require a distinct `approver` RBAC principal (`approver_id != operator_id`).
3. **At-Most-Once Idempotency:** Require a deterministic `idempotency_key`; duplicate execution requests return the original receipt with `idempotent_replay=true` and `execution_count == 1`.
4. **Post-Action Health Verification & Automatic Rollback:** Capture `pre_action_snapshot` before applying any change; if post-action verification fails, automatically restore `pre_action_snapshot` and record both `POST_CHECK_FAILED` and `AUTO_ROLLBACK_COMPLETED` in the SHA-256 hash-chained Iceberg audit log.

## Consequences
- **Benefits:** Eliminates double-execution bugs, guarantees reversible recovery, and yields tamper-evident compliance logs.
- **Tradeoffs:** Adds human review latency (budgeted at 60 seconds in MTTR benchmarks) compared to fully autonomous unsupervised execution, which is an intentional safety tradeoff for tier-0 data assets.
