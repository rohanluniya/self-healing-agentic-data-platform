#!/usr/bin/env bash
set -euo pipefail

PROFILE="${SRE_BOOTSTRAP_PROFILE:-local}"
HOST="${SRE_API_HOST:-0.0.0.0}"
PORT="${SRE_API_PORT:-8060}"

echo "[entrypoint] Bootstrapping Iceberg V2 Incident Evidence Lakehouse (profile=${PROFILE})..."
python /app/services/pipeline/run_pipeline.py --profile "${PROFILE}" --compact

echo "[entrypoint] Starting Agentic SRE Control Plane on http://${HOST}:${PORT}"
exec uvicorn main:app --app-dir /app/apps/control-plane-api --host "${HOST}" --port "${PORT}"
