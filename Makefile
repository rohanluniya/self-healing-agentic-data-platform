.PHONY: setup pipeline serve portable docker-standalone docker-core docker-full test chaos bench lint typecheck security clean

PYTHON := .venv/bin/python
UVICORN := .venv/bin/uvicorn

setup:
	uv sync --python 3.12 --extra dev

pipeline:
	$(PYTHON) services/pipeline/run_pipeline.py --profile local --compact

serve:
	$(UVICORN) main:app --app-dir apps/control-plane-api --host 127.0.0.1 --port 8060

portable:
	./scripts/run_portable.sh local

docker-standalone:
	docker compose -f docker-compose.standalone.yml up --build

docker-core:
	docker compose --profile core up -d

docker-full:
	docker compose --profile full up -d

test:
	.venv/bin/pytest -v

chaos:
	.venv/bin/pytest -v tests/chaos/test_chaos_fault_injection.py

bench:
	PYTHONPATH=. $(PYTHON) benchmarks/run_benchmarks.py

lint:
	.venv/bin/ruff check .

typecheck:
	.venv/bin/mypy agentic_sre ingestion models apps/control-plane-api/security.py

security:
	$(PYTHON) scripts/check_licenses.py

clean:
	rm -rf .local_data .pytest_cache .mypy_cache .ruff_cache .hypothesis
