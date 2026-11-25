"""End-to-end tests for the live FastAPI Control Plane API, RBAC auth, OPA endpoints, and remediation workflow."""

from __future__ import annotations

from fastapi.testclient import TestClient

VIEWER_HDR = {"X-API-Key": "dev-viewer-key-readonly"}
OPERATOR_HDR = {"X-API-Key": "dev-operator-key-ops"}
APPROVER_HDR = {"X-API-Key": "dev-approver-key-gov"}


def test_health_metrics_and_dashboard_html(api_client: TestClient) -> None:
    r_health = api_client.get("/health")
    assert r_health.status_code == 200
    body = r_health.json()
    assert body["status"] == "ok"
    assert body["default_agent_mode"] == "read_only"
    assert body["iceberg_tables_ready"] == 8

    r_metrics = api_client.get("/metrics")
    assert r_metrics.status_code == 200
    assert "sre_signals_ingested_total" in r_metrics.text

    r_ui = api_client.get("/")
    assert r_ui.status_code == 200
    assert "Self-Healing Operations Control Tower" in r_ui.text


def test_rbac_blocks_missing_invalid_and_cross_role_requests(api_client: TestClient) -> None:
    # Unauthenticated -> 401
    assert api_client.get("/v1/overview").status_code == 401
    # Invalid key -> 401
    assert api_client.get("/v1/overview", headers={"X-API-Key": "wrong-key"}).status_code == 401

    # Viewer can read overview & incidents
    r_ov = api_client.get("/v1/overview", headers=VIEWER_HDR)
    assert r_ov.status_code == 200
    assert r_ov.json()["audit_chain"]["valid"] is True

    # Viewer CANNOT propose dry-run -> 403
    r_dry_viewer = api_client.post(
        "/v1/remediations/dry-run",
        headers=VIEWER_HDR,
        json={
            "incident_id": "inc-any",
            "tool_name": "bounded_retry_task",
            "target_asset_id": "bronze.payments_raw",
            "parameters": {"max_retries": 2},
        },
    )
    assert r_dry_viewer.status_code == 403

    # Operator CANNOT approve -> 403
    plans = api_client.get("/v1/remediations", headers=OPERATOR_HDR).json()["plans"]
    pending = next(p for p in plans if p["status"] == "AWAITING_APPROVAL")
    r_op_appr = api_client.post(
        f"/v1/remediations/{pending['plan_id']}/approve",
        headers=OPERATOR_HDR,
        json={"comment": "self-approve attempt"},
    )
    assert r_op_appr.status_code == 403

    # Approver CANNOT execute -> 403
    r_appr_exec = api_client.post(
        f"/v1/remediations/{pending['plan_id']}/execute",
        headers=APPROVER_HDR,
        json={"idempotency_key": pending["idempotency_key"], "agent_mode_override": "guarded_active"},
    )
    assert r_appr_exec.status_code == 403


def test_e2e_evidence_opa_approve_execute_idempotency_and_rollback(api_client: TestClient) -> None:
    # 1. Inspect incidents & zero-hallucination evidence bundle
    incs = api_client.get("/v1/incidents", headers=VIEWER_HDR).json()["incidents"]
    bad_dep = next(i for i in incs if i["scenario_type"] == "bad_config_deployment")
    ev = api_client.get(f"/v1/incidents/{bad_dep['incident_id']}/evidence", headers=VIEWER_HDR).json()
    assert ev["hallucinated_evidence_rate"] == 0.0
    assert ev["verified_evidence_count"] == ev["total_evidence_count"]
    assert ev["hypotheses"][0]["root_asset_id"] == "silver.orders_enriched"

    # 2. Live OPA evaluation denies destructive drop_table
    pol_deny = api_client.post(
        "/v1/policy/evaluate",
        headers=VIEWER_HDR,
        json={
            "tool_name": "drop_table",
            "phase": "dry_run",
            "target_asset_id": "gold.daily_revenue_mv",
            "agent_mode": "guarded_active",
            "actor_role": "operator",
            "verified_evidence_count": 3,
        },
    ).json()
    assert pol_deny["allow"] is False
    assert pol_deny["risk_level"] == "forbidden"

    # 3. Operator dry-run of destructive tool returns HTTP 403
    r_bad_dry = api_client.post(
        "/v1/remediations/dry-run",
        headers=OPERATOR_HDR,
        json={
            "incident_id": bad_dep["incident_id"],
            "tool_name": "drop_table",
            "target_asset_id": "silver.orders_enriched",
            "parameters": {},
        },
    )
    assert r_bad_dry.status_code == 403

    # 4. Approver approves the bad_config_deployment rollback plan
    plans = api_client.get("/v1/remediations", headers=VIEWER_HDR).json()["plans"]
    rb_plan = next(p for p in plans if p["incident_id"] == bad_dep["incident_id"])
    r_appr = api_client.post(
        f"/v1/remediations/{rb_plan['plan_id']}/approve",
        headers=APPROVER_HDR,
        json={"comment": "Approved rollback to v2.13.4"},
    )
    assert r_appr.status_code == 200
    assert r_appr.json()["plan"]["status"] == "APPROVED"

    # 5. Operator executes twice with identical idempotency key -> second is idempotent_replay=True
    exec_payload = {
        "idempotency_key": rb_plan["idempotency_key"],
        "agent_mode_override": "guarded_active",
    }
    r_exec1 = api_client.post(
        f"/v1/remediations/{rb_plan['plan_id']}/execute",
        headers=OPERATOR_HDR,
        json=exec_payload,
    )
    assert r_exec1.status_code == 200
    assert r_exec1.json()["idempotent_replay"] is False
    assert r_exec1.json()["plan"]["status"] == "COMPLETED"

    r_exec2 = api_client.post(
        f"/v1/remediations/{rb_plan['plan_id']}/execute",
        headers=OPERATOR_HDR,
        json=exec_payload,
    )
    assert r_exec2.status_code == 200
    assert r_exec2.json()["idempotent_replay"] is True
    assert r_exec2.json()["plan"]["execution_count"] == 1

    # 6. Operator triggers manual rollback
    r_rb = api_client.post(
        f"/v1/remediations/{rb_plan['plan_id']}/rollback",
        headers=OPERATOR_HDR,
        json={"reason": "E2E rollback verification"},
    )
    assert r_rb.status_code == 200
    assert r_rb.json()["plan"]["status"] == "ROLLED_BACK"

    # 7. Audit chain remains cryptographically valid
    aud = api_client.get("/v1/audit", headers=VIEWER_HDR).json()
    assert aud["chain_valid"] is True
    assert aud["total_entries"] >= 12


def test_live_scenario_injection_endpoint(api_client: TestClient) -> None:
    r_inj = api_client.post(
        "/v1/scenarios/inject",
        headers=OPERATOR_HDR,
        json={"scenario": "false_positive_noisy_alert", "seed": 777},
    )
    assert r_inj.status_code == 200
    body = r_inj.json()
    assert body["signals_added"] == 1
    assert body["incidents_created"][0]["is_false_positive"] is True
