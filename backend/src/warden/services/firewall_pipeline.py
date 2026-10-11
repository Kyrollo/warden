from __future__ import annotations

import time
import uuid
from src.warden.domain.entities import (
    AuditIncident,
    FirewallAction,
    FirewallPolicy,
    InspectionFinding,
    InspectionResult,
    PiiEntity,
    ThreatCategory,
    ThreatSeverity,
)
from src.warden.services.classifier_engine import classify_semantic_intent
from src.warden.services.pii_engine import redact_pii
from src.warden.services.signature_engine import scan_signatures


async def execute_inbound_inspection(
    prompt: str,
    policy: FirewallPolicy,
    client_ip: str = "127.0.0.1",
    request_id: str | None = None,
) -> tuple[InspectionResult, AuditIncident | None]:
    """
    Executes the multi-stage firewall inspection pipeline on an inbound user prompt.
    Pipeline:
      Stage 1: Regex & Signature Scanning (<5ms)
      Stage 2: Semantic Intent & Zero-Shot Jailbreak Classifier (<150ms)
      Stage 3: PII & Sensitive Entity Redaction (<10ms)
    """
    total_start = time.perf_counter()
    req_id = request_id or f"req_{uuid.uuid4().hex[:12]}"
    findings: list[InspectionFinding] = []
    latencies: dict[str, float] = {}

    # Stage 1: Signature Scan
    sig_findings, sig_lat = scan_signatures(prompt, canary_token=policy.canary_token)
    findings.extend(sig_findings)
    latencies["regex_signature_scan_ms"] = sig_lat

    # Stage 2: Semantic Intent Classifier
    sem_findings, threat_score, sem_lat = await classify_semantic_intent(
        prompt,
        fail_mode=policy.fail_mode,
    )
    findings.extend(sem_findings)
    latencies["semantic_jailbreak_classifier_ms"] = sem_lat

    # Stage 3: PII Redaction
    sanitized_text = prompt
    pii_entities: list[PiiEntity] = []
    if policy.pii_masking_enabled:
        sanitized_text, pii_entities, pii_lat = redact_pii(prompt, allowed_types=policy.pii_types)
        latencies["pii_redaction_ms"] = pii_lat
    else:
        latencies["pii_redaction_ms"] = 0.0

    # Determine highest threat severity
    severity_order = [
        ThreatSeverity.CRITICAL,
        ThreatSeverity.HIGH,
        ThreatSeverity.MEDIUM,
        ThreatSeverity.LOW,
        ThreatSeverity.SAFE,
    ]
    highest_severity = ThreatSeverity.SAFE
    for s in severity_order:
        if any(f.severity == s for f in findings):
            highest_severity = s
            break

    # Determine Firewall Action based on policy
    action = FirewallAction.ALLOW
    blocked = False
    block_reason = None

    if highest_severity == ThreatSeverity.CRITICAL:
        action = policy.action_on_critical
        if action == FirewallAction.BLOCK:
            blocked = True
            block_reason = "Critical security threat detected: direct jailbreak or canary extraction attempt."
    elif highest_severity == ThreatSeverity.HIGH:
        action = policy.action_on_high
        if action == FirewallAction.BLOCK:
            blocked = True
            block_reason = "High adversarial risk detected: prompt injection pattern."
    elif pii_entities and policy.pii_masking_enabled:
        action = policy.action_on_pii
    elif highest_severity == ThreatSeverity.MEDIUM:
        action = FirewallAction.FLAG

    total_latency_ms = round((time.perf_counter() - total_start) * 1000, 2)
    latencies["total_pipeline_ms"] = total_latency_ms

    result = InspectionResult(
        request_id=req_id,
        input_text=prompt,
        sanitized_text=sanitized_text if not blocked else "[BLOCKED BY WARDEN FIREWALL]",
        action=action,
        threat_severity=highest_severity,
        threat_score=threat_score,
        findings=findings,
        pii_entities=pii_entities,
        stage_latencies=latencies,
        total_latency_ms=total_latency_ms,
        blocked=blocked,
        block_reason=block_reason,
    )

    # Generate Audit Incident if blocked, redacted, or flagged
    incident: AuditIncident | None = None
    if highest_severity in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH] or pii_entities:
        incident = AuditIncident(
            audit_id=f"AUDIT-{uuid.uuid4().hex[:8].upper()}",
            client_ip=client_ip,
            request_id=req_id,
            prompt_preview=prompt[:120] + ("..." if len(prompt) > 120 else ""),
            action=action,
            threat_severity=highest_severity,
            blocked_reason=block_reason or ("PII Redaction Applied" if pii_entities else "Suspicious Pattern"),
            resolution="REJECTED" if blocked else ("REDACTED" if pii_entities else "FLAGGED"),
            stage_latencies=latencies,
        )

    return result, incident
