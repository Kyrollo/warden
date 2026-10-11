from __future__ import annotations

import re
import time
from src.warden.domain.entities import PiiEntity

PII_REGEX_RULES = [
    (
        "EMAIL",
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b",
        "[REDACTED_EMAIL]",
    ),
    (
        "SSN",
        r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
        "[REDACTED_SSN]",
    ),
    (
        "PHONE",
        r"\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        "[REDACTED_PHONE]",
    ),
    (
        "API_KEY",
        r"\b(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|AKIA[0-9A-Z]{16})\b",
        "[REDACTED_API_KEY]",
    ),
    (
        "CREDIT_CARD",
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        "[REDACTED_CREDIT_CARD]",
    ),
    (
        "MEDICAL_ID",
        r"\bMRN-\d{6,8}\b",
        "[REDACTED_MEDICAL_ID]",
    ),
]


def luhn_checksum(card_number: str) -> bool:
    """Verify standard Luhn check on credit card digits."""
    digits = [int(d) for d in card_number if d.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled if doubled < 10 else doubled - 9
        else:
            checksum += digit
    return checksum % 10 == 0


def redact_pii(
    text: str,
    allowed_types: list[str] | None = None,
) -> tuple[str, list[PiiEntity], float]:
    """
    Scans for personally identifiable information (PII) and sensitive tokens.
    Replaces matched tokens with structured masks in-place.
    """
    start_time = time.perf_counter()
    entities: list[PiiEntity] = []
    sanitized = text

    types_to_scan = set(allowed_types or ["EMAIL", "SSN", "PHONE", "API_KEY", "CREDIT_CARD", "MEDICAL_ID"])

    # Collect matches first
    matches_to_replace = []
    for entity_type, pattern, mask in PII_REGEX_RULES:
        if entity_type not in types_to_scan:
            continue

        for m in re.finditer(pattern, text):
            raw_val = m.group(0)
            # If credit card, optional Luhn verification
            if entity_type == "CREDIT_CARD" and not luhn_checksum(raw_val):
                continue

            matches_to_replace.append((m.start(), m.end(), entity_type, raw_val, mask))

    # Sort descending by start index to replace cleanly without offset skew
    matches_to_replace.sort(key=lambda x: x[0], reverse=True)

    for start_idx, end_idx, entity_type, raw_val, mask in matches_to_replace:
        entities.append(
            PiiEntity(
                entity_type=entity_type,
                raw_value=raw_val,
                masked_value=mask,
                start=start_idx,
                end=end_idx,
            )
        )
        sanitized = sanitized[:start_idx] + mask + sanitized[end_idx:]

    latency_ms = round((time.perf_counter() - start_time) * 1000, 3)
    return sanitized, entities, latency_ms
