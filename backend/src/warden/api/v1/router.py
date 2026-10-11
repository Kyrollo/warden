from __future__ import annotations

from fastapi import APIRouter
from .health import router as health_router
from .auth import router as auth_router

api_v1_router = APIRouter()
api_v1_router.include_router(health_router)
api_v1_router.include_router(auth_router)


@api_v1_router.get("/info", tags=["info"])
async def get_system_info() -> dict[str, str]:
    return {
        "name": "Warden",
        "slug": "warden",
        "archetype": "Security audit report",
        "version": "1.0.0",
        "description": "AI Security Red-Teaming & Guardrails: OWASP LLM Top 10 automated scanner and low-latency runtime safety guardrails",
    }
