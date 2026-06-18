# IR Platform (Local-First)

Incident response platform that runs primary analysis entirely on your MacBook using LM Studio.
Claude API is used minimally — only for specific knowledge gaps the local model can't fill.

## Architecture

```
Endpoints (Workstations, Servers, VMs)
          │
          ▼
  Velociraptor Server ──── Collects forensic artifacts via VQL
          │
          ▼
  ┌── MacBook M4 Pro 48GB ─────────────────────────────┐
  │                                                     │
  │  ┌─ Docker ──────────────────────────────────────┐  │
  │  │  FastAPI Orchestrator                         │  │
  │  │      │                                        │  │
  │  │      ▼                                        │  │
  │  │  Step 1: PII Anonymization (regex + LLM)      │  │
  │  │      │                                        │  │
  │  │      ▼                                        │  │
  │  │  Step 2: Primary Analysis (local LLM)         │  │
  │  │      │                                        │  │
  │  │      ▼                                        │  │
  │  │  Step 3: Confidence Check                     │  │
  │  │      │           │                            │  │
  │  │  ≥ threshold  < threshold                     │  │
  │  │      │           │                            │  │
  │  │      ▼           ▼                            │  │
  │  │  Done ✓    Step 4: Cloud (targeted Q&A)       │  │
  │  │                  │                            │  │
  │  │                  ▼                            │  │
  │  │            Merge + Report                     │  │
  │  │                                               │  │
  │  │  React Dashboard (:3000)                      │  │
  │  └───────────────────────────────────────────────┘  │
  │                                                     │
  │  LM Studio (native, :1234) ◄── Qwen2.5-14B         │
  └─────────────────────────────────────────────────────┘
```

## What stays local vs. what goes to the cloud

| Step | Where | What happens |
|------|-------|-------------|
| Collection | Local | Velociraptor pulls artifacts from endpoints |
| Anonymization | Local | Regex + LLM strip all PII (IPs, hostnames, usernames, org names) |
| Primary analysis | Local | IOC extraction, MITRE mapping, timeline, severity, recommendations |
| Confidence check | Local | LLM self-assesses what it knows vs. doesn't |
| Second local pass | Local | Focused prompts try to resolve gaps locally |
| Cloud escalation | Cloud | ONLY anonymized questions go to Claude — never raw data |
| De-anonymization | Local | Real values restored for analyst viewing only |

Claude typically receives 5-15 targeted questions per incident, not the full forensic dump.
You can disable cloud entirely with `allow_cloud: false`.

## When does the local model escalate to Claude?

The local LLM flags specific knowledge gaps:

- **Threat intel**: Unknown file hashes, suspicious domains not in training data
- **Malware families**: Unrecognized C2 frameworks or malware behaviors
- **CVE details**: Recent vulnerabilities the local model hasn't seen
- **Attribution**: Novel TTPs that might map to specific APT groups
- **Detection rules**: YARA/Sigma rules for specific indicators

The analyst controls escalation via:
- **allow_cloud** toggle: on/off (default: on)
- **cloud_threshold** slider: confidence level below which to escalate (default: 70%)
- **Manual approval**: review what will be sent before it goes

## Quick Start

### 1. LM Studio

Install [LM Studio](https://lmstudio.ai), download a model, start the server:

| Model | RAM | Speed | Quality |
|-------|-----|-------|---------|
| Qwen2.5-7B-Instruct | ~8GB | Fast | Good |
| **Qwen2.5-14B-Instruct** | **~16GB** | **Medium** | **Very Good** ← recommended |
| Mistral-Small-24B | ~24GB | Slower | Excellent |
| Llama-3.3-70B-Q4 | ~40GB | Slow | Best |

Verify: `curl http://localhost:1234/v1/models`

### 2. Configure

```bash
cp .env.example .env
# Edit: ANTHROPIC_API_KEY, VELOCIRAPTOR_API_URL, LM_STUDIO_MODEL
```

### 3. Launch

```bash
docker compose up --build
```

- **Dashboard**: http://localhost:3000
- **API docs**: http://localhost:8000/docs

### 4. Health check

```bash
curl http://localhost:8000/api/health
```

```json
{
  "status": "ok",
  "lm_studio_reachable": true,
  "lm_studio_model": "qwen2.5-14b-instruct",
  "velociraptor_reachable": true,
  "claude_api_configured": true
}
```

## API Usage

### Full pipeline (100% local)

```bash
curl -X POST http://localhost:8000/api/pipeline/full \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "C.1234567890abcdef",
    "artifacts": ["processes", "network", "autoruns"],
    "incident_title": "Suspicious process",
    "context": "AV alert for cobalt strike beacon",
    "allow_cloud": false
  }'
```

### Full pipeline (local + cloud if needed)

```bash
curl -X POST http://localhost:8000/api/pipeline/full \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "C.1234567890abcdef",
    "artifacts": ["processes", "network", "eventlog"],
    "incident_title": "Potential lateral movement",
    "allow_cloud": true,
    "cloud_threshold": 0.7
  }'
```

### Preview what would go to Claude

```bash
curl http://localhost:8000/api/incidents/{id}/escalation/estimate
```

Returns the questions, estimated tokens, and cost before you approve.

### Manually approve cloud escalation

```bash
curl -X POST http://localhost:8000/api/incidents/{id}/escalation/approve
```

## Project Structure

```
ir-platform/
├── docker-compose.yml
├── Dockerfile                    # Backend
├── Dockerfile.frontend           # Frontend (Vite + nginx)
├── .env.example
├── backend/
│   ├── requirements.txt
│   └── app/
│       ├── main.py               # FastAPI routes
│       ├── config.py             # Pydantic settings
│       ├── models.py             # Data models + enums
│       ├── orchestrator.py       # Pipeline coordinator
│       ├── velociraptor_client.py # Artifact collection
│       ├── anonymizer.py         # PII removal (regex + LLM)
│       ├── local_analyzer.py     # Primary analysis (LM Studio)
│       └── cloud_escalator.py    # Targeted Claude queries
└── frontend/
    ├── package.json
    ├── vite.config.js
    ├── nginx.conf
    ├── index.html
    └── src/
        ├── main.jsx
        └── App.jsx               # IR dashboard
```

## Security

- **No raw data leaves the machine** — Claude receives only anonymized questions
- **Analyst controls cloud access** — toggle, threshold, manual approval
- **PII mappings stay in memory** — not persisted to disk by default
- **De-anonymization is local only** — real values never sent externally
- **Velociraptor TLS** — self-signed certs accepted (pin in production)
