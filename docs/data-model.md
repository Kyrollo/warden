# Data Model & Entity Specifications

## 1. Entity Relationship Diagram (ERD)

```mermaid
erDiagram
    FirewallPolicy ||--o{ InspectionResult : governs
    FirewallPolicy ||--o{ AuditIncident : triggers
    InspectionResult ||--|{ InspectionFinding : contains
    InspectionResult ||--|{ PiiEntity : identifies
    OutputInspectionResult ||--|{ InspectionFinding : contains
    RedTeamPreset ||--o{ InspectionResult : validates

    FirewallPolicy {
        string id PK
        string name
        string description
        boolean enabled
        float injection_sensitivity
        float jailbreak_threshold
        boolean pii_masking_enabled
        string_array pii_types
        string canary_token
        string action_on_critical
        string action_on_high
        string action_on_pii
        string fail_mode
    }

    InspectionResult {
        string request_id PK
        timestamp timestamp
        string input_text
        string sanitized_text
        string action
        string threat_severity
        float threat_score
        float total_latency_ms
        boolean blocked
        string block_reason
    }

    InspectionFinding {
        string rule_id PK
        string category
        string severity
        float confidence
        string message
        string matched_text
    }

    PiiEntity {
        string entity_type
        string raw_value
        string masked_value
        int start
        int end
    }

    OutputInspectionResult {
        string request_id PK
        timestamp timestamp
        string output_text
        string sanitized_output
        string action
        string threat_severity
        boolean canary_leaked
        boolean system_leakage_detected
        boolean blocked
    }

    AuditIncident {
        string audit_id PK
        timestamp timestamp
        string client_ip
        string request_id FK
        string prompt_preview
        string action
        string threat_severity
        string blocked_reason
        string resolution
    }

    RedTeamPreset {
        string id PK
        string name
        string category
        string prompt
        string expected_severity
        string expected_action
    }
```

---

## 2. Threat Severity & Category Matrix

| Threat Category | Default Severity | Inspection Stage | Description |
| :--- | :---: | :---: | :--- |
| `PROMPT_INJECTION` | `CRITICAL` / `HIGH` | Stage 1 & Stage 2 | Direct or indirect attempts to override instructions or redefine system boundaries. |
| `JAILBREAK` | `CRITICAL` | Stage 1 & Stage 2 | Persona hijacking exploits (DAN, Developer Mode, Grandparent roleplay). |
| `CANARY_EXTRACTION`| `CRITICAL` | Stage 1 & Stage 4 | Probing or exfiltrating secret session canary tokens. |
| `PII_LEAKAGE` | `MEDIUM` | Stage 3 | Transmission of personal identifiable data (SSN, credit card, email, phone, API key). |
| `SYSTEM_LEAKAGE` | `HIGH` | Stage 1 & Stage 4 | Probing or outputting hidden system prompt instructions. |
| `HARMFUL_ADVICE` | `CRITICAL` | Stage 2 & Stage 4 | Destructive shell commands (`rm -rf /`) or physical hazard instructions. |
| `BENIGN` | `SAFE` | - | Standard user query satisfying enterprise safety policy. |
