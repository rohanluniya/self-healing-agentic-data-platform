"""Runtime configuration for the Self-Healing Data Platform Control Plane."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class Settings:
    """Immutable settings loaded from environment variables with safe local defaults."""

    runtime_mode: str = "local_native"
    data_dir: Path = REPO_ROOT / ".local_data"
    api_host: str = "127.0.0.1"
    api_port: int = 8060

    # Safety posture: read-only diagnosis by default.
    agent_mode: str = "read_only"
    require_approval: bool = True
    enforce_sod: bool = True

    # Optional remote OPA endpoint; falls back to embedded Rego-equivalent evaluator.
    opa_policy_url: str = ""

    # Optional local LLM narration adapter (disabled by default; zero weight downloads).
    enable_local_llm: bool = False
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "llama3.2:3b"

    # Development RBAC API keys (override via secrets manager in production).
    viewer_api_key: str = "dev-viewer-key-readonly"
    operator_api_key: str = "dev-operator-key-ops"
    approver_api_key: str = "dev-approver-key-gov"

    @property
    def warehouse_dir(self) -> Path:
        return self.data_dir / "warehouse"

    @property
    def catalog_db(self) -> Path:
        return self.data_dir / "iceberg_catalog.db"

    @property
    def raw_stream_dir(self) -> Path:
        return self.data_dir / "raw_stream"

    @property
    def state_dir(self) -> Path:
        return self.data_dir / "state"

    @property
    def logs_dir(self) -> Path:
        return self.data_dir / "logs"

    def ensure_dirs(self) -> None:
        for path in (
            self.data_dir,
            self.warehouse_dir,
            self.raw_stream_dir,
            self.state_dir,
            self.logs_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)


def _as_bool(raw: str | None, default: bool) -> bool:
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def load_settings(data_dir_override: Path | str | None = None) -> Settings:
    """Load settings from process environment."""
    raw_dir = data_dir_override or os.getenv("SRE_DATA_DIR")
    data_dir = Path(raw_dir).resolve() if raw_dir else (REPO_ROOT / ".local_data")
    return Settings(
        runtime_mode=os.getenv("SRE_RUNTIME_MODE", "local_native"),
        data_dir=data_dir,
        api_host=os.getenv("SRE_API_HOST", "127.0.0.1"),
        api_port=int(os.getenv("SRE_API_PORT", "8060")),
        agent_mode=os.getenv("SRE_AGENT_MODE", "read_only"),
        require_approval=_as_bool(os.getenv("SRE_REQUIRE_APPROVAL"), True),
        enforce_sod=_as_bool(os.getenv("SRE_ENFORCE_SOD"), True),
        opa_policy_url=os.getenv("OPA_POLICY_URL", "").strip(),
        enable_local_llm=_as_bool(os.getenv("ENABLE_LOCAL_LLM"), False),
        ollama_base_url=os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434"),
        ollama_model=os.getenv("OLLAMA_MODEL", "llama3.2:3b"),
        viewer_api_key=os.getenv("SRE_VIEWER_API_KEY", "dev-viewer-key-readonly"),
        operator_api_key=os.getenv("SRE_OPERATOR_API_KEY", "dev-operator-key-ops"),
        approver_api_key=os.getenv("SRE_APPROVER_API_KEY", "dev-approver-key-gov"),
    )
