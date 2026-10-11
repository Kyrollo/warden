from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from src.warden.domain.entities import InspectionResult, OutputInspectionResult
from src.warden.services.firewall_pipeline import execute_inbound_inspection
from src.warden.services.output_inspector import inspect_model_output
from src.warden.services.store import store

router = APIRouter(prefix="/inspect", tags=["inspect"])


class InspectInputRequest(BaseModel):
    prompt: str
    policy_id: str = "policy_genai_enterprise"


class InspectOutputRequest(BaseModel):
    output_text: str
    policy_id: str = "policy_genai_enterprise"
    request_id: str | None = None


@router.post("/input", response_model=InspectionResult)
async def inspect_input(req: InspectInputRequest, request: Request) -> InspectionResult:
    """Inspect an inbound user prompt through the multi-stage firewall pipeline."""
    policy = store.policies.get(req.policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail=f"Policy {req.policy_id} not found")

    client_ip = request.client.host if request.client else "127.0.0.1"
    result, incident = await execute_inbound_inspection(req.prompt, policy=policy, client_ip=client_ip)

    # Append to store traffic stream & incidents
    store.traffic_stream.insert(
        0,
        {
            "request_id": result.request_id,
            "timestamp": result.timestamp.isoformat(),
            "source_ip": client_ip,
            "input_prompt_preview": req.prompt[:120] + ("..." if len(req.prompt) > 120 else ""),
            "threat_severity": result.threat_severity.value,
            "action": result.action.value,
            "resolution": "REJECTED" if result.blocked else ("REDACTED" if result.pii_entities else "ALLOWED"),
            "latencies": result.stage_latencies,
        },
    )
    if incident:
        store.incidents.insert(0, incident)

    return result


@router.post("/output", response_model=OutputInspectionResult)
async def inspect_output(req: InspectOutputRequest) -> OutputInspectionResult:
    """Inspect an outbound model completion for canary leaks and dangerous commands."""
    policy = store.policies.get(req.policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail=f"Policy {req.policy_id} not found")

    return inspect_model_output(
        output_text=req.output_text,
        canary_token=policy.canary_token,
        request_id=req.request_id,
    )
