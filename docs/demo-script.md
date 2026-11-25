# Live Demo Script (5-Minute Walkthrough)

## Prerequisites
Start the control plane in one command (zero Docker required):
```bash
./scripts/run_portable.sh local
```
Open `http://127.0.0.1:8060/` in a browser.

## Step 1: Verify Service Health, Metrics & Default Safe Posture
```bash
curl -s http://127.0.0.1:8060/health | python3 -m json.tool
curl -s http://127.0.0.1:8060/metrics | grep -E "^sre_(signals|incidents|opa|hallucinated)"
```
Confirm `default_agent_mode: "read_only"`, `iceberg_tables_ready: 8`, and `optional_local_llm_enabled: false`.

## Step 2: Inspect RBAC Enforcement (401 & 403)
```bash
# Unauthenticated -> 401
curl -i http://127.0.0.1:8060/v1/overview | head -n 1

# Viewer trying to propose a dry-run mutation -> 403
curl -i -X POST http://127.0.0.1:8060/v1/remediations/dry-run \
  -H "X-API-Key: dev-viewer-key-readonly" \
  -H "Content-Type: application/json" \
  -d '{"incident_id":"inc-test","tool_name":"bounded_retry_task","target_asset_id":"bronze.payments_raw","parameters":{"max_retries":2}}' | head -n 1
```

## Step 3: Inspect Zero-Hallucination Evidence Bundle & OPA Hard-Denial
In the Control Tower UI (`http://127.0.0.1:8060/`):
1. Click **Bad Config Deployment rooted at `silver.orders_enriched`** — note the red root-cause node and amber downstream blast radius on the OpenLineage graph.
2. Inspect the **RCA Evidence Bundle** showing `15/15 Verified · 0.0% Hallucinated` citations (`signal_id`, `span_id`, `commit_version:v2.14.0`, `lineage_edge`).
3. Click **Deny `drop_table`** and **Deny 365-part backfill** in the **Live OPA Adversarial Policy Guardrail Tester** to observe instant Rego policy rejections.

## Step 4: Execute Separation-of-Duties Approval -> Idempotent Execution -> Rollback
1. Switch the top-right RBAC persona dropdown to **Approver** and click **2. Approve (Approver)**.
2. Switch back to **Operator** and click **3b. Simulate Failed Post-Check (Auto-Rollback)** (or **3. Execute (Guarded Active)** followed by **4. Manual Rollback**).
3. Observe the **Immutable SHA-256 Remediation Audit Log** at the bottom update in real time with a verified hash chain!
