# Warden

> **Automated vulnerability scanner and runtime protection for LLM applications**

[![CI](https://github.com/Kyrollo/warden/actions/workflows/ci.yml/badge.svg)](https://github.com/Kyrollo/warden/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![Coverage](https://img.shields.io/badge/coverage-%E2%89%A580%25-brightgreen.svg)](tests/)

AI Security Red-Teaming & Guardrails: OWASP LLM Top 10 automated scanner and low-latency runtime safety guardrails

---

## Architecture Overview

```mermaid
flowchart TD
    Client["Client / Browser"] -->|"HTTP / SSE"| Web["Frontend (React 19 + Tailwind v4)\nPort 3003"]
    Web -->|"REST API /v1"| API["FastAPI Backend\nPort 8003"]
    API -->|"Async ORM"| DB[("PostgreSQL 16")]
    API -->|"Tasks / Cache"| Redis[("Redis 7")]
    API -->|"Async Celery Worker"| Worker["Worker Process"]
    API -->|"Provider-Agnostic HTTP"| LLM["LLM Provider (Ollama / Cloud)"]
    API -->|"Telemetry & Spans"| Observability["OpenTelemetry + Langfuse + Prometheus"]
```

## Quickstart

### Prerequisites
- Docker & Docker Compose OR Python 3.12+ & Node 22+
- Local Ollama running (`ollama serve`) or cloud LLM API key

### Running with Docker Compose
```bash
# 1. Clone repository
git clone https://github.com/Kyrollo/warden.git
cd warden

# 2. Configure environment
cp .env.example .env

# 3. Start complete stack (Database, Redis, API, Frontend)
docker compose -f deploy/compose.dev.yml up --build
```

Access services:
- **Web Console**: [http://localhost:3003](http://localhost:3003)
- **Backend API**: [http://localhost:8003](http://localhost:8003)
- **API Documentation**: [http://localhost:8003/docs](http://localhost:8003/docs)
- **Metrics**: [http://localhost:8003/metrics](http://localhost:8003/metrics)

---

## Repository Structure

```text
warden/
├── backend/            # FastAPI async backend, domain logic, AI pipelines
├── frontend/           # React 19 + Vite + Tailwind CSS v4 frontend
├── evaluation/         # Reproducible evaluation harness and benchmarks
├── docs/               # Complete MkDocs Material technical documentation
├── deploy/             # Docker Compose configurations (dev, prod, gpu)
├── scripts/            # CI validation, smoke tests, utility scripts
└── .github/workflows/  # CI/CD pipelines
```

## License
MIT License. See [LICENSE](LICENSE) for details.
