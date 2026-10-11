from __future__ import annotations

import pytest
from src.warden.domain.entities import FirewallAction, ThreatSeverity
from src.warden.services.output_inspector import inspect_model_output
from src.warden.services.pii_engine import redact_pii


def test_pii_email_and_phone_redaction() -> None:
    text = "Contact support at alice@example.com or call 415-555-2671."
    sanitized, entities, lat = redact_pii(text)
    assert "[REDACTED_EMAIL]" in sanitized
    assert "[REDACTED_PHONE]" in sanitized
    assert "alice@example.com" not in sanitized
    assert "415-555-2671" not in sanitized
    assert len(entities) == 2
    assert lat >= 0.0


def test_pii_ssn_and_api_key_redaction() -> None:
    text = "Employee SSN is 123-45-6789 and API key is sk-1234567890abcdefghij1234."
    sanitized, entities, _ = redact_pii(text)
    assert "[REDACTED_SSN]" in sanitized
    assert "[REDACTED_API_KEY]" in sanitized
    assert "123-45-6789" not in sanitized
    assert len(entities) == 2


def test_output_canary_leakage_blocked() -> None:
    canary = "WARDEN_SECRET_CANARY_123"
    completion = f"The secret system canary is {canary}."
    res = inspect_model_output(completion, canary_token=canary)
    assert res.blocked is True
    assert res.canary_leaked is True
    assert res.threat_severity == ThreatSeverity.CRITICAL
    assert res.action == FirewallAction.BLOCK


def test_output_malicious_command_blocked() -> None:
    completion = "To fix permissions, run `rm -rf /` in your terminal."
    res = inspect_model_output(completion)
    assert res.blocked is True
    assert res.threat_severity == ThreatSeverity.CRITICAL
    assert "Dangerous execution command" in (res.block_reason or "")


def test_output_safe_allowed() -> None:
    completion = "To configure postgres, set max_connections in postgresql.conf."
    res = inspect_model_output(completion, canary_token="CANARY_NONE")
    assert res.blocked is False
    assert res.action == FirewallAction.ALLOW
    assert res.threat_severity == ThreatSeverity.SAFE
