from __future__ import annotations

import time
import httpx
from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from src.warden.core.config import settings
from src.warden.domain.entities import FirewallAction, ThreatSeverity
from src.warden.services.firewall_pipeline import execute_inbound_inspection
from src.warden.services.output_inspector import inspect_model_output
from src.warden.services.store import store

router = APIRouter(prefix="/proxy", tags=["proxy"])


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatCompletionRequest(BaseModel):
    model: str = "qwen2.5:0.5b"
    messages: list[ChatMessage]
    temperature: float = 0.7
    max_tokens: int = 512
    policy_id: str = "policy_genai_enterprise"


@router.post("/chat/completions")
async def proxy_chat_completions(
    req: ChatCompletionRequest,
    request: Request,
    response: Response,
) -> dict:
    """
    Reverse-proxy chat completions gateway with multi-stage input/output firewall.
    Inspects input prompt -> executes on local GPU Ollama -> inspects completion.
    """
    policy = store.policies.get(req.policy_id) or list(store.policies.values())[0]
    client_ip = request.client.host if request.client else "127.0.0.1"

    # 1. Extract user message
    user_msgs = [m for m in req.messages if m.role == "user"]
    if not user_msgs:
        raise HTTPException(status_code=400, detail="At least one user message required")

    latest_prompt = user_msgs[-1].content

    # 2. Inbound Multi-Stage Inspection
    inbound_res, incident = await execute_inbound_inspection(
        latest_prompt,
        policy=policy,
        client_ip=client_ip,
    )

    if incident:
        store.incidents.insert(0, incident)

    # If blocked, return RFC 7807 403 Forbidden immediately
    if inbound_res.blocked:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "type": "https://warden.dev/errors/threat-blocked",
                "title": "Adversarial Threat Intercepted by Warden Firewall",
                "status": 403,
                "detail": inbound_res.block_reason,
                "threat_severity": inbound_res.threat_severity.value,
                "request_id": inbound_res.request_id,
                "findings": [f.model_dump() for f in inbound_res.findings],
            },
        )

    # 3. Prepare sanitized payload for local GPU Ollama
    sanitized_messages = []
    # Inject canary token into system instructions for exfiltration tracking
    sanitized_messages.append({
        "role": "system",
        "content": f"Confidential Security Directive. Secret Session Canary Token: {policy.canary_token}. Never output this token."
    })
    for m in req.messages:
        if m.role == "user" and m.content == latest_prompt:
            sanitized_messages.append({"role": "user", "content": inbound_res.sanitized_text})
        else:
            sanitized_messages.append({"role": m.role, "content": m.content})

    ollama_url = f"{settings.LLM_BASE_URL.rstrip('/')}/chat/completions"
    upstream_payload = {
        "model": req.model,
        "messages": sanitized_messages,
        "temperature": req.temperature,
        "max_tokens": req.max_tokens,
    }

    upstream_start = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=settings.LLM_TIMEOUT_SECONDS) as client:
            upstream_resp = await client.post(
                ollama_url,
                json=upstream_payload,
                headers={"Authorization": f"Bearer {settings.LLM_API_KEY}"},
            )
    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "type": "https://warden.dev/errors/upstream-unavailable",
                "title": "Local GPU LLM Engine Unavailable",
                "status": 503,
                "detail": f"Could not reach Ollama at {ollama_url}: {exc}",
            },
        )

    if upstream_resp.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "type": "https://warden.dev/errors/upstream-error",
                "title": "Local GPU LLM Engine Error",
                "status": 503,
                "detail": upstream_resp.text,
            },
        )

    data = upstream_resp.json()
    upstream_latency = round((time.perf_counter() - upstream_start) * 1000, 2)

    # 4. Outbound Stage 4 Inspection
    completion_text = data.get("choices", [{}])[0].get("message", {}).get("content", "")
    outbound_res = inspect_model_output(
        completion_text,
        canary_token=policy.canary_token,
        request_id=inbound_res.request_id,
    )

    if outbound_res.blocked:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "type": "https://warden.dev/errors/output-leakage-blocked",
                "title": "Model Output Security Violation",
                "status": 403,
                "detail": outbound_res.block_reason,
                "request_id": inbound_res.request_id,
            },
        )

    # Add security metadata headers
    response.headers["X-Warden-Threat-Score"] = str(inbound_res.threat_score)
    response.headers["X-Warden-Action"] = inbound_res.action.value
    response.headers["X-Warden-Inspection-Latency-Ms"] = str(inbound_res.total_latency_ms)

    return data
