from __future__ import annotations

from fastapi import APIRouter
from src.warden.domain.entities import AuditIncident
from src.warden.services.store import store

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("", response_model=list[AuditIncident])
async def list_audit_incidents() -> list[AuditIncident]:
    """Retrieve security audit incident log of blocked or flagged prompts."""
    return store.incidents


@router.get("/traffic", response_model=list[dict])
async def get_traffic_stream() -> list[dict]:
    """Retrieve real-time intercepted prompt traffic stream with latencies."""
    return store.traffic_stream[:50]
