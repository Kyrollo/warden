from __future__ import annotations

from fastapi import APIRouter
from src.warden.api.v1.auth import router as auth_router
from src.warden.api.v1.health import router as health_router
from src.warden.api.v1.incidents import router as incidents_router
from src.warden.api.v1.inspect import router as inspect_router
from src.warden.api.v1.lab import router as lab_router
from src.warden.api.v1.policies import router as policies_router
from src.warden.api.v1.proxy import router as proxy_router

api_v1_router = APIRouter()
api_v1_router.include_router(health_router)
api_v1_router.include_router(auth_router)
api_v1_router.include_router(inspect_router)
api_v1_router.include_router(proxy_router)
api_v1_router.include_router(policies_router)
api_v1_router.include_router(incidents_router)
api_v1_router.include_router(lab_router)


@api_v1_router.get("/info", tags=["info"])
async def get_system_info() -> dict[str, str]:
    return {
        "name": "Warden",
        "slug": "warden",
        "archetype": "SOC Firewall",
        "version": "1.0.0",
        "description": "LLM Safety, Hallucination & Prompt Injection Firewall: runtime input/output safety guardrails",
    }
