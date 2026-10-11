from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


class ThreatSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    SAFE = "SAFE"


class ThreatCategory(str, Enum):
    PROMPT_INJECTION = "PROMPT_INJECTION"
    JAILBREAK = "JAILBREAK"
    PII_LEAKAGE = "PII_LEAKAGE"
    CANARY_EXTRACTION = "CANARY_EXTRACTION"
    SYSTEM_LEAKAGE = "SYSTEM_LEAKAGE"
    TOXICITY = "TOXICITY"
    HARMFUL_ADVICE = "HARMFUL_ADVICE"
    BENIGN = "BENIGN"


class FirewallAction(str, Enum):
    BLOCK = "BLOCK"
    REDACT = "REDACT"
    FLAG = "FLAG"
    ALLOW = "ALLOW"


class PiiEntity(BaseModel):
    entity_type: str  # EMAIL, SSN, PHONE, CREDIT_CARD, API_KEY, MEDICAL_ID
    raw_value: str
    masked_value: str
    start: int
    end: int


class InspectionFinding(BaseModel):
    rule_id: str
    category: ThreatCategory
    severity: ThreatSeverity
    confidence: float
    message: str
    matched_text: str | None = None


class InspectionResult(BaseModel):
    request_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    input_text: str
    sanitized_text: str
    action: FirewallAction
    threat_severity: ThreatSeverity
    threat_score: float  # 0.0 to 1.0
    findings: list[InspectionFinding] = Field(default_factory=list)
    pii_entities: list[PiiEntity] = Field(default_factory=list)
    stage_latencies: dict[str, float] = Field(default_factory=dict)
    total_latency_ms: float = 0.0
    blocked: bool = False
    block_reason: str | None = None


class OutputInspectionResult(BaseModel):
    request_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    output_text: str
    sanitized_output: str
    action: FirewallAction
    threat_severity: ThreatSeverity
    canary_leaked: bool = False
    system_leakage_detected: bool = False
    findings: list[InspectionFinding] = Field(default_factory=list)
    stage_latencies: dict[str, float] = Field(default_factory=dict)
    total_latency_ms: float = 0.0
    blocked: bool = False
    block_reason: str | None = None


class FirewallPolicy(BaseModel):
    id: str
    name: str
    description: str
    enabled: bool = True
    injection_sensitivity: float = 0.80
    jailbreak_threshold: float = 0.85
    pii_masking_enabled: bool = True
    pii_types: list[str] = Field(
        default_factory=lambda: ["EMAIL", "SSN", "PHONE", "CREDIT_CARD", "API_KEY"]
    )
    canary_token: str = "WARDEN_CANARY_SECRET_7X9Q"
    action_on_critical: FirewallAction = FirewallAction.BLOCK
    action_on_high: FirewallAction = FirewallAction.BLOCK
    action_on_pii: FirewallAction = FirewallAction.REDACT
    fail_mode: str = "FAIL_CLOSED"  # FAIL_CLOSED or FAIL_OPEN


class AuditIncident(BaseModel):
    audit_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    client_ip: str
    request_id: str
    prompt_preview: str
    action: FirewallAction
    threat_severity: ThreatSeverity
    blocked_reason: str
    resolution: str  # REJECTED, REDACTED, FLAGGED, ALLOWED
    stage_latencies: dict[str, float] = Field(default_factory=dict)


class RedTeamPreset(BaseModel):
    id: str
    name: str
    category: str
    prompt: str
    expected_severity: ThreatSeverity
    expected_action: FirewallAction
    description: str
