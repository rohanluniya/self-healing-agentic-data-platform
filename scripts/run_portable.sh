#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PROFILE="${1:-local}"
HOST="${SRE_API_HOST:-127.0.0.1}"
PORT="${SRE_API_PORT:-8060}"

cd "${REPO_ROOT}"

if command -v uv >/dev/null 2>&1; then
  uv sync --python 3.12 --extra dev
else
  python3 -m venv .venv
  .venv/bin/pip install --upgrade pip
  .venv/bin/pip install -e ".[dev]"
fi

.venv/bin/python services/pipeline/run_pipeline.py --profile "${PROFILE}" --compact
echo "Starting Self-Healing Operations Control Tower on http://${HOST}:${PORT}"
exec .venv/bin/uvicorn main:app --app-dir apps/control-plane-api --host "${HOST}" --port "${PORT}"
