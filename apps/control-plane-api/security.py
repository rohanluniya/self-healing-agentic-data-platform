"""RBAC API-Key Authentication and Role Authorization for the Control Plane API."""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from fastapi import Header, HTTPException, status

from agentic_sre.config import Settings, load_settings


@dataclass(frozen=True)
class Principal:
    actor_id: str
    role: str  # viewer | operator | approver


def resolve_principal(api_key: str | None, settings: Settings | None = None) -> Principal:
    """Authenticate an X-API-Key header using constant-time comparison."""
    cfg = settings or load_settings()
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header",
        )
    if secrets.compare_digest(api_key, cfg.viewer_api_key):
        return Principal(actor_id="sre-viewer-01", role="viewer")
    if secrets.compare_digest(api_key, cfg.operator_api_key):
        return Principal(actor_id="sre-operator-01", role="operator")
    if secrets.compare_digest(api_key, cfg.approver_api_key):
        return Principal(actor_id="sre-approver-01", role="approver")
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid X-API-Key credential",
    )


def require_roles(allowed_roles: set[str]):
    """FastAPI dependency enforcing RBAC roles (viewer, operator, approver)."""

    def _dependency(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> Principal:
        principal = resolve_principal(x_api_key)
        if principal.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{principal.role}' is not authorized; required one of {sorted(allowed_roles)}",
            )
        return principal

    return _dependency
