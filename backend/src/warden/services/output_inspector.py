from __future__ import annotations

import re
import time
import uuid
from src.warden.domain.entities import (
    FirewallAction,
    InspectionFinding,
    OutputInspectionResult,
    ThreatCategory,
    ThreatSeverity,
)

MALICIOUS_COMMANDS = [
    r"\brm\s+-rf\s+[/~*]",
    r"\bmkfs\b",
    r"(?i)\bcat\s+/etc/(shadow|passwd)\b",
    r"(?i)\bpowershell\s+-(enc|encodedcommand)\b",
    r"(?i)\bcurl\s+.*\|\s*(bash|sh)\b",
    r"\b/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+\b",
]

SYSTEM_LEAK_PHRASES = [
    r"(?i)\b(my\s+confidential\s+system\s+instructions\s+are|internal\s+system\s+prompt\s+revealed)\b",
    r"(?i)\b(here\s+are\s+the\s+hidden\s+rules\s+given\s+to\s+me)\b",
]


def inspect_model_output(
    output_text: str,
    canary_token: str | None = None,
    request_id: str | None = None,
) -> OutputInspectionResult:
    """Inspects model completions for canary token leakage and dangerous commands."""
    start_time = time.perf_counter()
    req_id = request_id or f"out_{uuid.uuid4().hex[:10]}"
    findings: list[InspectionFinding] = []
    canary_leaked = False
    system_leakage = False
    action = FirewallAction.ALLOW
    severity = ThreatSeverity.SAFE
    blocked = False
    block_reason = None

    # 1. Canary Token Verification
    if canary_token and canary_token in output_text:
        canary_leaked = True
        severity = ThreatSeverity.CRITICAL
        action = FirewallAction.BLOCK
        blocked = True
        block_reason = "System secret canary token exfiltrated in model output."
        findings.append(
            InspectionFinding(
                rule_id="OUT-CANARY-LEAK",
                category=ThreatCategory.CANARY_EXTRACTION,
                severity=ThreatSeverity.CRITICAL,
                confidence=1.0,
                message="Canary token detected in model output completion.",
                matched_text=canary_token,
            )
        )

    # 2. Malicious Command Verification
    for idx, pattern in enumerate(MALICIOUS_COMMANDS, start=1):
        match = re.search(pattern, output_text)
        if match:
            severity = ThreatSeverity.CRITICAL
            action = FirewallAction.BLOCK
            blocked = True
            block_reason = f"Dangerous execution command generated in output: {match.group(0)}"
            findings.append(
                InspectionFinding(
                    rule_id=f"OUT-MAL-CMD-{idx:02d}",
                    category=ThreatCategory.HARMFUL_ADVICE,
                    severity=ThreatSeverity.CRITICAL,
                    confidence=0.98,
                    message=f"Malicious shell/execution syntax detected in model output: '{match.group(0)}'",
                    matched_text=match.group(0),
                )
            )
            break

    # 3. System Prompt Leakage
    for idx, pattern in enumerate(SYSTEM_LEAK_PHRASES, start=1):
        match = re.search(pattern, output_text)
        if match:
            system_leakage = True
            if severity != ThreatSeverity.CRITICAL:
                severity = ThreatSeverity.HIGH
                action = FirewallAction.BLOCK
                blocked = True
                block_reason = "Verbatim system prompt instruction leak detected."
            findings.append(
                InspectionFinding(
                    rule_id=f"OUT-SYS-LEAK-{idx:02d}",
                    category=ThreatCategory.SYSTEM_LEAKAGE,
                    severity=ThreatSeverity.HIGH,
                    confidence=0.95,
                    message="Verbatim system prompt disclosure pattern identified.",
                    matched_text=match.group(0),
                )
            )

    latency_ms = round((time.perf_counter() - start_time) * 1000, 3)

    return OutputInspectionResult(
        request_id=req_id,
        output_text=output_text,
        sanitized_output="[BLOCKED BY WARDEN FIREWALL: CRITICAL THREAT DETECTED]" if blocked else output_text,
        action=action,
        threat_severity=severity,
        canary_leaked=canary_leaked,
        system_leakage_detected=system_leakage,
        findings=findings,
        stage_latencies={"output_leakage_ms": latency_ms},
        total_latency_ms=latency_ms,
        blocked=blocked,
        block_reason=block_reason,
    )
