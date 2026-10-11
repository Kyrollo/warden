from __future__ import annotations

import base64
import re
import time
from src.warden.domain.entities import InspectionFinding, ThreatCategory, ThreatSeverity

# Regex patterns for direct adversarial prompt injection signatures
SIGNATURE_PATTERNS = [
    (
        r"(?i)\b(ignore|disregard|forget|override)\s+(all\s+)?(previous|prior|above|system)\s+(instructions?|rules?|directives?|prompts?)\b",
        ThreatCategory.PROMPT_INJECTION,
        ThreatSeverity.CRITICAL,
        0.98,
        "Direct instruction override attempt detected.",
    ),
    (
        r"(?i)\b(dan\s+\d+|do\s+anything\s+now|developer\s+mode\s+enabled|jailbreak|unfiltered\s+mode)\b",
        ThreatCategory.JAILBREAK,
        ThreatSeverity.CRITICAL,
        0.99,
        "Known jailbreak persona pattern detected (DAN/Developer Mode).",
    ),
    (
        r"(?i)\b(pretend\s+you\s+have\s+no\s+rules|act\s+as\s+an\s+unrestricted\s+ai|you\s+are\s+now\s+evil)\b",
        ThreatCategory.JAILBREAK,
        ThreatSeverity.HIGH,
        0.92,
        "Adversarial roleplay jailbreak pattern detected.",
    ),
    (
        r"(?i)\b(print|reveal|show|output|leak|repeat)\s+(your\s+)?(system\s+prompt|initial\s+instructions?|system\s+instructions?|hidden\s+rules?)\b",
        ThreatCategory.SYSTEM_LEAKAGE,
        ThreatSeverity.HIGH,
        0.94,
        "System prompt exfiltration pattern detected.",
    ),
    (
        r"(?i)\b(what\s+is\s+the\s+canary|warden_canary|canary\s+token)\b",
        ThreatCategory.CANARY_EXTRACTION,
        ThreatSeverity.CRITICAL,
        0.97,
        "Canary token probing attack detected.",
    ),
    (
        r"(?i)\b(grandmother|grandma)\s+used\s+to\s+read\s+me\s+napalm\b",
        ThreatCategory.JAILBREAK,
        ThreatSeverity.CRITICAL,
        0.99,
        "Known grandmother exploit signature detected.",
    ),
]

BASE64_PATTERN = re.compile(r"\b[A-Za-z0-9+/]{28,}={0,2}\b")


def scan_signatures(text: str, canary_token: str | None = None) -> tuple[list[InspectionFinding], float]:
    """
    Executes high-performance regex pattern inspection.
    Returns detected findings and execution latency in milliseconds.
    """
    start_time = time.perf_counter()
    findings: list[InspectionFinding] = []

    # 1. Canary Token Check
    if canary_token and canary_token.lower() in text.lower():
        findings.append(
            InspectionFinding(
                rule_id="SIG-CANARY-01",
                category=ThreatCategory.CANARY_EXTRACTION,
                severity=ThreatSeverity.CRITICAL,
                confidence=1.0,
                message="Secret canary token detected in prompt text.",
                matched_text=canary_token,
            )
        )

    # 2. Signature Patterns
    for idx, (pattern, category, severity, conf, msg) in enumerate(SIGNATURE_PATTERNS, start=1):
        match = re.search(pattern, text)
        if match:
            findings.append(
                InspectionFinding(
                    rule_id=f"SIG-PAT-{idx:02d}",
                    category=category,
                    severity=severity,
                    confidence=conf,
                    message=msg,
                    matched_text=match.group(0),
                )
            )

    # 3. Encoded Payload Detection
    for b64_match in BASE64_PATTERN.finditer(text):
        raw_b64 = b64_match.group(0)
        try:
            decoded = base64.b64decode(raw_b64).decode("utf-8", errors="ignore")
            # Scan decoded payload recursively against signatures
            for pattern, category, severity, conf, msg in SIGNATURE_PATTERNS[:3]:
                if re.search(pattern, decoded):
                    findings.append(
                        InspectionFinding(
                            rule_id="SIG-B64-OBFUSCATION",
                            category=category,
                            severity=ThreatSeverity.CRITICAL,
                            confidence=0.96,
                            message=f"Obfuscated Base64 payload containing adversarial injection: '{decoded[:40]}...'",
                            matched_text=raw_b64,
                        )
                    )
                    break
        except Exception:
            pass

    latency_ms = round((time.perf_counter() - start_time) * 1000, 3)
    return findings, latency_ms
