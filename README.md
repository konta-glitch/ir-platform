# IR Platform

Local-first incident response platform with AI-assisted analysis (local LLM
+ optional Claude escalation), Sigma rule detection, and an interactive
investigation agent.

## Architecture

```
backend/app/
├── main.py              # FastAPI routes (thin — delegates to orchestrator)
├── orchestrator.py       # Pipeline coordinator (thin — delegates to services)
├── services.py           # Domain services: Incident, Pipeline, Escalation, Agent
├── plugins/               # Artifact analyzer plugins (process, network, event...)
├── models.py              # Pydantic models incl. unified Artifact model
├── detection_engine.py    # Forensic rule engine (LOLBins, suspicious cmdlines...)
├── sigma_engine.py        # Sigma rule evaluation
├── correlation_engine.py  # Timeline, process trees, frequency analysis
├── local_analyzer.py      # Local LLM (LM Studio) analysis
├── cloud_escalator.py     # Claude API escalation for knowledge gaps
├── anonymizer.py          # PII redaction before any cloud call
├── investigation_agent.py # LLM agent that queries artifacts interactively
├── database.py            # SQLite persistence
└── report_generator.py    # Markdown/structured report output

frontend/                 # React + Vite UI
sigma_rules/               # Built-in + Hayabusa Sigma rules
collectors/                 # Standalone Windows/Linux collection scripts
```

## Setup

```bash
cp .env.example .env
# edit .env: set ANTHROPIC_API_KEY if you want cloud escalation

docker compose up --build
```

Backend: `http://localhost:8000`
Frontend: `http://localhost:5173` (or as configured)

## Development

```bash
cd backend
python -m venv venv
source venv/bin/activate   # or venv\Scripts\activate on Windows
pip install -r requirements.txt
uvicorn app.main:app --reload
```

```bash
cd frontend
npm install
npm run dev
```

## Design principles

- **Thin orchestrator** — `orchestrator.py` only sequences calls; all logic
  lives in `services.py` and the engine modules.
- **Plugin-based artifact parsing** — new collectors (MFT, Prefetch, Browser…)
  implement `AnalyzerPlugin` and register in `PluginRegistry`, with zero
  changes to the detection/correlation pipeline.
- **Unified `Artifact` model** — every parser emits the same normalized shape,
  so correlation and Sigma evaluation don't special-case data sources.
- **Cloud-boundary anonymization only** — the local LLM always sees real data;
  PII is redacted only if/when something is sent to Claude, and de-anonymized
  immediately on return.
