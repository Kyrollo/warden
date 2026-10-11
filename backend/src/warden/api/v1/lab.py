from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from src.warden.domain.entities import (
    InspectionFinding,
    PiiEntity,
    RedTeamPreset,
    ThreatSeverity,
)
from src.warden.services.firewall_pipeline import execute_inbound_inspection
from src.warden.services.store import store

router = APIRouter(prefix="/lab", tags=["lab"])


class RedTeamAttackRequest(BaseModel):
    prompt: str
    policy_id: str = "policy_genai_enterprise"


class RedTeamAttackResponse(BaseModel):
    prompt: str
    sanitized_text: str
    action: str
    threat_severity: ThreatSeverity
    threat_score: float  # 0.0 to 1.0
    blocked: bool
    block_reason: str | None
    findings: list[InspectionFinding]
    pii_entities: list[PiiEntity]
    stage_latencies: dict[str, float]
    total_latency_ms: float


@router.get("/presets", response_model=list[RedTeamPreset])
async def list_attack_presets() -> list[RedTeamPreset]:
    """Retrieve pre-loaded red-team attack presets for interactive testing."""
    return store.presets


@router.post("/attack", response_model=RedTeamAttackResponse)
async def run_red_team_attack(req: RedTeamAttackRequest, request: Request) -> RedTeamAttackResponse:
    """Execute live red-team adversarial prompt attack against firewall pipeline."""
    policy = store.policies.get(req.policy_id) or list(store.policies.values())[0]
    client_ip = request.client.host if request.client else "127.0.0.1"

    result, incident = await execute_inbound_inspection(
        req.prompt,
        policy=policy,
        client_ip=client_ip,
    )

    if incident:
        store.incidents.insert(0, incident)

    return RedTeamAttackResponse(
        prompt=req.prompt,
        sanitized_text=result.sanitized_text,
        action=result.action.value,
        threat_severity=result.threat_severity,
        threat_score=result.threat_score,
        blocked=result.blocked,
        block_reason=result.block_reason,
        findings=result.findings,
        pii_entities=result.pii_entities,
        stage_latencies=result.stage_latencies,
        total_latency_ms=result.total_latency_ms,
    )
