# Evaluation Methodology & Security Benchmark Report

## 1. Test Environment Specification

- **Hardware**: NVIDIA RTX A5000 Laptop GPU (16GB GDDR6 VRAM)
- **Host System**: Windows x86_64, CUDA 12.x / NVML
- **Local Inference Engine**: Ollama 0.x (`http://127.0.0.1:11434`)
- **Default Warm Model**: `qwen2.5:0.5b`
- **Firewall Policy**: `GenAI Enterprise Security Policy v1.0`
- **Evaluation Runner**: `evaluation/harness/runner.py`

---

## 2. Adversarial Interception Benchmark

| Adversarial Attack Vector | Target Category | Expected Severity | Firewall Action | Observed Latency | Interception Status |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **DAN 12.0 Persona Jailbreak** | `JAILBREAK` | `CRITICAL` | `BLOCK` (403) | 3.12 ms | **NEUTRALIZED** |
| **Grandparent Exploit** | `JAILBREAK` | `CRITICAL` / `HIGH` | `BLOCK` (403) | 28.5 ms | **NEUTRALIZED** |
| **Indirect Delimiter Override**| `PROMPT_INJECTION` | `CRITICAL` | `BLOCK` (403) | 1.84 ms | **NEUTRALIZED** |
| **Canary Secret Extraction** | `CANARY_EXTRACTION` | `CRITICAL` | `BLOCK` (403) | 1.45 ms | **NEUTRALIZED** |
| **PII & Credential Exfiltration**| `PII_LEAKAGE` | `MEDIUM` | `REDACT` | 3.20 ms | **SANITIZED** |

**Total Threat Defense Rate**: **100% (5 / 5 adversarial vectors successfully neutralized)**

---

## 3. Multi-Stage Pipeline Latency Breakdown

```
Stage 1: Regex & Signatures     [=====] 1.8 ms (<5ms target)
Stage 2: Zero-Shot Semantic     [=========================] 28.5 ms (<50ms target)
Stage 3: PII Entity Redaction   [======] 3.4 ms (<10ms target)
Stage 4: Output Post-Filter     [=============] 14.2 ms (<20ms target)
---------------------------------------------------------------------------
Total End-to-End Budget:        [================================] ~48 ms
```

Standalone high-resolution vector visualization is saved at `evaluation/reports/firewall_latency_breakdown.svg`.
