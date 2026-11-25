"""CLI interface for operating the Self-Healing Data Platform Control Plane."""

from __future__ import annotations

import argparse
import json
import sys

from agentic_sre.config import load_settings
from agentic_sre.lakehouse import IcebergEvidenceLakehouse
from agentic_sre.platform_model import PlatformStateStore
from agentic_sre.remediation import RemediationEngine
from services.pipeline.run_pipeline import run_end_to_end_pipeline


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="agentic-sre", description="Agentic SRE Data Platform CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_pipe = sub.add_parser("run-pipeline", help="Run deterministic telemetry -> Iceberg V2 -> RCA -> DQ pipeline")
    p_pipe.add_argument("--profile", choices=["smoke", "local", "stress"], default="local")
    p_pipe.add_argument("--seed", type=int, default=42)
    p_pipe.add_argument("--compact", action="store_true")

    sub.add_parser("status", help="Inspect current Iceberg V2 lakehouse analytics and DQ summary")

    p_appr = sub.add_parser("approve", help="Approve a pending remediation plan as approver")
    p_appr.add_argument("plan_id")
    p_appr.add_argument("--actor", default="cli-approver")
    p_appr.add_argument("--comment", default="Approved via CLI")

    p_exec = sub.add_parser("execute", help="Execute an approved remediation plan with idempotency key")
    p_exec.add_argument("plan_id")
    p_exec.add_argument("--idempotency-key", required=True)
    p_exec.add_argument("--actor", default="cli-operator")
    p_exec.add_argument("--guarded-active", action="store_true")

    p_rb = sub.add_parser("rollback", help="Roll back an executed remediation plan")
    p_rb.add_argument("plan_id")
    p_rb.add_argument("--actor", default="cli-operator")
    p_rb.add_argument("--reason", default="CLI rollback")

    args = parser.parse_args(argv)
    cfg = load_settings()
    cfg.ensure_dirs()

    if args.command == "run-pipeline":
        res = run_end_to_end_pipeline(profile=args.profile, seed=args.seed, compact=args.compact)
        print(json.dumps(res["analytics"], indent=2))
        return

    lakehouse = IcebergEvidenceLakehouse(cfg.warehouse_dir, cfg.catalog_db)
    if args.command == "status":
        print(
            json.dumps(
                {
                    "analytics": lakehouse.duckdb_analytics_summary(),
                    "tables": lakehouse.table_stats(),
                },
                indent=2,
            )
        )
        return

    state_store = PlatformStateStore(cfg.state_dir / "platform_state.json")
    engine = RemediationEngine(settings=cfg, lakehouse=lakehouse, state_store=state_store)

    if args.command == "approve":
        plan = engine.approve_plan(
            plan_id=args.plan_id, approver_id=args.actor, approver_role="approver", comment=args.comment
        )
        print(plan.model_dump_json(indent=2))
    elif args.command == "execute":
        plan, replayed = engine.execute_plan(
            plan_id=args.plan_id,
            idempotency_key=args.idempotency_key,
            operator_id=args.actor,
            operator_role="operator",
            agent_mode_override="guarded_active" if args.guarded_active else None,
        )
        print(json.dumps({"replayed": replayed, "plan": plan.model_dump()}, indent=2))
    elif args.command == "rollback":
        plan = engine.rollback_plan(
            plan_id=args.plan_id, operator_id=args.actor, operator_role="operator", reason=args.reason
        )
        print(plan.model_dump_json(indent=2))


if __name__ == "__main__":
    main(sys.argv[1:])
