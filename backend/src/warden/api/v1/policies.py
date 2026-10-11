from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from src.warden.domain.entities import FirewallAction, FirewallPolicy
from src.warden.services.store import store

router = APIRouter(prefix="/policies", tags=["policies"])


class UpdatePolicyRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    enabled: bool | None = None
    injection_sensitivity: float | None = None
    jailbreak_threshold: float | None = None
    pii_masking_enabled: bool | None = None
    pii_types: list[str] | None = None
    canary_token: str | None = None
    action_on_critical: FirewallAction | None = None
    action_on_high: FirewallAction | None = None
    action_on_pii: FirewallAction | None = None
    fail_mode: str | None = None


@router.get("", response_model=list[FirewallPolicy])
async def list_policies() -> list[FirewallPolicy]:
    """List all registered firewall security policies."""
    return list(store.policies.values())


@router.get("/{policy_id}", response_model=FirewallPolicy)
async def get_policy(policy_id: str) -> FirewallPolicy:
    """Retrieve details for a specific firewall policy."""
    policy = store.policies.get(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail=f"Policy {policy_id} not found")
    return policy


@router.put("/{policy_id}", response_model=FirewallPolicy)
async def update_policy(policy_id: str, req: UpdatePolicyRequest) -> FirewallPolicy:
    """Update active firewall policy thresholds, PII masking rules, or actions."""
    policy = store.policies.get(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail=f"Policy {policy_id} not found")

    updated_data = req.model_dump(exclude_unset=True)
    new_policy = policy.model_copy(update=updated_data)
    store.policies[policy_id] = new_policy
    return new_policy
