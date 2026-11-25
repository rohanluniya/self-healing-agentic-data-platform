"""Shared pytest fixtures for isolated Iceberg V2 lakehouse and FastAPI Control Plane testing."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agentic_sre.config import Settings
from agentic_sre.lakehouse import IcebergEvidenceLakehouse
from agentic_sre.platform_model import PlatformStateStore
from agentic_sre.telemetry import TelemetryHub


@pytest.fixture()
def isolated_settings(tmp_path: Path) -> Settings:
    cfg = Settings(
        runtime_mode="local_native",
        data_dir=tmp_path / "sre_data",
        agent_mode="read_only",
        require_approval=True,
        enforce_sod=True,
        enable_local_llm=False,
    )
    cfg.ensure_dirs()
    return cfg


@pytest.fixture()
def isolated_lakehouse(isolated_settings: Settings) -> IcebergEvidenceLakehouse:
    return IcebergEvidenceLakehouse(isolated_settings.warehouse_dir, isolated_settings.catalog_db)


@pytest.fixture()
def isolated_state(isolated_settings: Settings) -> PlatformStateStore:
    return PlatformStateStore(isolated_settings.state_dir / "platform_state.json")


@pytest.fixture()
def isolated_telemetry() -> TelemetryHub:
    return TelemetryHub(service_name="test-agentic-sre")


@pytest.fixture()
def api_client(isolated_settings: Settings, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("SRE_DATA_DIR", str(isolated_settings.data_dir))
    monkeypatch.setenv("SRE_AGENT_MODE", "read_only")
    monkeypatch.setenv("ENABLE_LOCAL_LLM", "false")
    main_path = Path(__file__).resolve().parent.parent / "apps" / "control-plane-api" / "main.py"
    spec = importlib.util.spec_from_file_location("control_plane_main_test", main_path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    app = mod.create_app(settings_override=isolated_settings)
    return TestClient(app)
