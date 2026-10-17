# System Architecture & Technical Design

## 1. Overview
**Warden** is an enterprise runtime security and policy firewall for Large Language Model (LLM) applications. It intercepts inbound user queries and outbound model responses to detect adversarial prompt injection attacks, persona hijacking jailbreaks (DAN, Developer Mode, roleplay manipulation), sensitive PII leakage (SSNs, credit cards, API keys), and system prompt canary exfiltration.

---

## 2. C4 Container Diagram

```mermaid
flowchart TD
    subgraph Clients ["Client Applications"]
        UserBrowser["Security Analyst Browser\nPort 3003"]
        AppClient["Enterprise Chat Application\n(SDK / API Client)"]
    end

    subgraph Warden_Firewall ["Warden Firewall Stack"]
        Frontend["Warden SOC UI (React 19 + Tailwind v4)\nPort 3003"]
        Gateway["Warden FastAPI Gateway & Reverse Proxy\nPort 8003"]

        subgraph Inspection_Pipeline ["Multi-Stage Inspection Engine"]
            Stage1["Stage 1: Regex & Signature Pre-Filter\n(<5ms budget)"]
            Stage2["Stage 2: Zero-Shot Semantic Classifier\n(Ollama GPU Inference)"]
            Stage3["Stage 3: PII Entity Redaction\n(Typed Masking)"]
            Stage4["Stage 4: Output Leakage Checker\n(Canary & Command Guard)"]
        end

        PolicyEngine["Policy & Audit Engine\n(BLOCK / REDACT / FLAG / ALLOW)"]
        Store[("In-Memory & Audit Incident Log\nTraffic Telemetry Stream")]
    end

    subgraph Upstream_LLMs ["Inference Backends"]
        LocalGPU["Local NVIDIA Dedicated NVIDIA GPU\nOllama: qwen2.5:0.5b (Warm)"]
        CloudLLM["Cloud Failover LLM\n(OpenAI / Anthropic)"]
    end

    UserBrowser --> Frontend
    Frontend --> Gateway
    AppClient -->|POST /proxy/chat/completions| Gateway

    Gateway --> Stage1
    Stage1 --> Stage2
    Stage2 --> Stage3
    Stage3 --> PolicyEngine

    PolicyEngine -->|Threat Neutralized (403)| AppClient
    PolicyEngine -->|Sanitized Prompt| LocalGPU
    PolicyEngine -->|Fallback| CloudLLM

    LocalGPU --> Stage4
    Stage4 --> AppClient
    PolicyEngine --> Store
```

---

## 3. Reverse-Proxy Inspection Sequence

```mermaid
sequenceDiagram
    autonumber
    actor Client as Enterprise User / App Client
    participant Proxy as Warden Proxy Gateway (/proxy/chat/completions)
    participant S1 as Stage 1: Regex Scan
    participant S2 as Stage 2: Semantic Classifier (GPU)
    participant S3 as Stage 3: PII Redactor
    participant Ollama as Upstream LLM (Dedicated NVIDIA GPU)
    participant S4 as Stage 4: Output Inspector

    Client->>Proxy: POST /proxy/chat/completions (prompt, model)
    Proxy->>S1: scan_signatures(prompt, canary_token)
    alt Direct Signature Breach (e.g. DAN / Canary Probe)
        S1-->>Proxy: ThreatSeverity=CRITICAL
        Proxy-->>Client: HTTP 403 Forbidden (RFC 7807 Problem Details)
    else Signature Clean
        S1-->>Proxy: Clean (<2ms)
        Proxy->>S2: classify_semantic_intent(prompt)
        S2-->>Proxy: ThreatScore & Category
        Proxy->>S3: redact_pii(prompt)
        S3-->>Proxy: sanitized_prompt (with [REDACTED_*] tokens)
        Proxy->>Ollama: POST /chat/completions (sanitized_prompt + canary)
        Ollama-->>Proxy: 200 OK (model completion)
        Proxy->>S4: inspect_model_output(completion, canary_token)
        alt Canary Exfiltrated or Malicious Shell Command
            S4-->>Proxy: Output Blocked
            Proxy-->>Client: HTTP 403 Forbidden (Output Violation)
        else Output Clean
            S4-->>Proxy: Clean
            Proxy-->>Client: 200 OK (safe completion + safety headers)
        end
    end
```

---

## 4. Threat Action State Machine

```mermaid
stateDiagram-v2
    [*] --> IngestPrompt: User Prompt Ingested
    IngestPrompt --> CheckSignatures: Stage 1 Regex Scan

    CheckSignatures --> BlockThreat: Critical Signature Match (DAN/Canary)
    CheckSignatures --> CheckSemantic: Clean Signature

    CheckSemantic --> BlockThreat: Threat Score >= Threshold
    CheckSemantic --> CheckPII: Threat Score < Threshold

    CheckPII --> RedactPII: PII Entities Found
    CheckPII --> AllowPrompt: No PII Found

    RedactPII --> ForwardToLLM: Masked Prompt [REDACTED_*]
    AllowPrompt --> ForwardToLLM: Original Prompt
    BlockThreat --> HTTP_403: RFC 7807 Forbidden

    ForwardToLLM --> CheckOutput: Stage 4 Output Inspection
    CheckOutput --> HTTP_403: Canary Token Leaked / Dangerous Command
    CheckOutput --> HTTP_200: Safe Response Delivered

    HTTP_403 --> [*]
    HTTP_200 --> [*]
```
