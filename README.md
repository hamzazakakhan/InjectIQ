# InjectIQ v2

**AI-Native Database Exploitation Framework**

[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

InjectIQ is an AI-native, autonomous database exploitation framework designed for authorized penetration testing and red team engagements. It unifies SQL, NoSQL, and GraphQL injection techniques with real-time AI analysis via Ollama to dynamically adapt payloads, bypass modern WAFs, and achieve full data extraction with minimal manual intervention.

> **Disclaimer:** This tool is intended for authorized security testing only. Use against systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal.

---

## Features

- **Multi-Database Injection Engine**
  - SQL: MySQL, PostgreSQL, MSSQL, Oracle, SQLite, MariaDB
  - NoSQL: MongoDB, Redis, Cassandra, DynamoDB, Elasticsearch
  - GraphQL: Apollo, Hasura, and generic endpoints

- **AI Copilot (Ollama Integration)**
  - Real-time WAF response analysis and custom tamper generation
  - False-positive elimination via pattern recognition
  - Novel bypass technique generation for unknown WAFs
  - Autonomous decision-making for extraction strategy

- **WAF & CDN Bypass**
  - Cloudflare, Akamai, Imperva, AWS WAF, F5 ASM, Fortinet
  - CDN origin discovery and direct backend targeting
  - Dynamic tamper script selection per WAF fingerprint

- **Advanced Techniques**
  - HTTP Request Smuggling (HRS) for WAF bypass
  - Parameterized Query Bypass
  - Second-Order Injection
  - Time-based, Error-based, Union-based, Boolean-based, Stacked queries
  - Out-of-band (OOB) extraction via DNS/HTTP

- **Autonomous Operation**
  - Full pipeline: Probe → Fingerprint → Bypass → Extract → Report
  - Minimal configuration required for standard engagements

---

## Architecture

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Probe     │───▶│  Payload    │───▶│   Inject    │───▶│  Extract    │
│   Engine    │    │   Engine    │    │   Engine    │    │   Engine    │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
       │                   │                  │
       ▼                   ▼                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         AI Copilot (Ollama)                          │
│  WAF Analysis • Tamper Generation • Decision Logic • False-Pos      │
└─────────────────────────────────────────────────────────────────────┘
```

| Module | Purpose |
|--------|---------|
| `probe.py` | Endpoint discovery, WAF fingerprinting, DBMS identification, CDN origin bypass |
| `payload.py` | Payload generation per technique per DBMS, tamper engine |
| `inject.py` | Orchestrates the full injection loop with AI feedback |
| `comparator.py` | Response differential analysis, true/false determination |
| `smuggling.py` | HTTP Request Smuggling (TE.CL, CL.TE) attacks |
| `param_bypass.py` | Parameterized query bypass and second-order injection |
| `ai_copilot.py` | Ollama integration for real-time AI analysis |
| `cli.py` | Click-based CLI interface |

---

## Installation

```bash
git clone https://github.com/hamzazakakhan/injectiq.git
cd injectiq
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**Optional: AI Copilot**
Install Ollama and pull a model:
```bash
ollama pull qwen2.5-coder:7b
```

---

## Usage

### Quick Scan
```bash
python -m injectiq scan --url "https://target.com/page?id=1"
```

### GraphQL Target
```bash
python -m injectiq scan --url "https://target.com/graphql" --graphql
```

### POST Body Injection
```bash
python -m injectiq scan --url "https://target.com/api" \
    --method POST \
    --data '{"q":"test"}'
```

### HTTP Request Smuggling
```bash
python -m injectiq smuggle --url "https://target.com"
```

### Parameterized Query Bypass
```bash
python -m injectiq bypass --url "https://target.com/page?id=1"
```

### Second-Order Injection
```bash
python -m injectiq second-order \
    --store-url "https://target.com/register" \
    --trigger-url "https://target.com/admin"
```

### Full Autonomous Dump
```bash
python -m injectiq dump --url "https://target.com/page?id=1" --dbms mysql
```

---

## Requirements

- Python 3.10+
- `httpx>=0.27.0`
- `click>=8.1.0`
- Ollama (optional, for AI copilot)

---

## Training Data

- `sqlmap_tamper_training.json` — Historical WAF bypass payloads for ML training

---

## License

MIT License — See [LICENSE](LICENSE) for details.

---

## Author

**Hamza Zaka Khan** — [github.com/hamzazakakhan](https://github.com/hamzazakakhan)
