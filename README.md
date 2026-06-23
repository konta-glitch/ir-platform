# IR Platform

Local-first incident response platform with AI-assisted analysis (local LLM
+ optional Claude escalation), Sigma + YARA detection, and an interactive
investigation agent.

> **Local-first by design.** The local LLM always sees real data. PII is
> redacted *only* at the cloud boundary (if/when something is escalated to
> Claude) and de-anonymized immediately on return.

## Repository layout

```
backend/            FastAPI service — analysis pipeline & engines
frontend/           React + Vite UI
collectors/         Standalone Windows/Linux artifact collection scripts
sigma_rules/        Sigma rules (built-in committed; curated sets fetched)
scripts/            Setup, install, diagnostic & build helpers
docs/               Setup guide, validation playbook
```

### Backend internals

```
backend/app/
├── main.py                 # FastAPI routes (thin — delegates to orchestrator)
├── orchestrator.py         # Pipeline coordinator (thin — delegates to services)
├── services.py             # Domain services: Incident, Pipeline, Escalation, Agent
├── models.py               # Pydantic models incl. unified Artifact model
│
├── plugins/                # Artifact analyzer plugins (one parser per file)
│   ├── __init__.py         #   AnalyzerPlugin contract + PluginRegistry
│   ├── process_plugin.py
│   ├── network_plugin.py
│   ├── event_plugin.py
│   ├── filesystem_plugin.py
│   └── persistence_plugin.py
│
├── detection/              # Modular forensic detection engine
│   ├── base.py             #   DetectionEngine core + routing table
│   ├── processes.py        #   process / service / scheduled-task detection
│   ├── network.py          #   network connections (ports, beaconing)
│   ├── dns_dga.py          #   DNS / DGA / tunneling
│   ├── eventlogs.py        #   Windows Event Log detection
│   ├── auth_patterns.py    #   authentication pattern analysis
│   ├── defender.py         #   Windows Defender (EVTX + MPLog)
│   ├── persistence.py      #   registry persistence + LNK
│   ├── execution_evidence.py  # Prefetch / Amcache / Shimcache / UserAssist
│   ├── file_anomalies.py   #   file metadata anomalies
│   ├── sysmon.py           #   Sysmon-specific detection
│   ├── textlogs.py         #   text/syslog detection
│   ├── yara_findings.py    #   YARA match interpretation
│   ├── behavior_correlation.py # cross-finding attack chains
│   ├── risk_scoring.py     #   process/entity risk aggregation
│   ├── clustering.py       #   group findings into one entity
│   └── generic.py          #   fallback for unrecognized artifacts
│
├── sigma_engine.py         # Sigma rule evaluation
├── yara_scanner.py         # YARA compilation + scanning
├── correlation_engine.py   # Timeline, process trees, frequency analysis
├── local_analyzer.py       # Local LLM (LM Studio) analysis
├── lm_client.py            # LLM transport client
├── cloud_escalator.py      # Claude API escalation for knowledge gaps
├── anonymizer.py           # PII redaction before any cloud call
├── investigation_agent.py  # LLM agent that queries artifacts interactively
├── rag_engine.py           # Retrieval over artifacts/context
├── image_analyzer.py       # Disk/memory image handling
├── collector.py            # Server-side collection coordination
├── database.py             # SQLite persistence
├── report_generator.py     # Markdown / structured report output
├── progress.py             # Pipeline progress tracking
├── structured_logging.py   # JSON structured logs
└── config.py               # Settings
```

## Quick start

```bash
cp .env.example .env
# edit .env: set ANTHROPIC_API_KEY if you want cloud escalation

docker compose up --build
```

- Backend:  `http://localhost:8000`
- Frontend: `http://localhost:5173`

### Detection rules

Both rulesets **auto-update in the background on container start** — Sigma
(Hayabusa) and YARA (YARA-Forge) alike. The update is best-effort: it never
blocks startup, and the platform works immediately on first boot from the
committed starter sets (`backend/yara_rules/starter_rules.yar` and
`sigma_rules/builtin_rules.yml`). Refresh cadence and the YARA package size
are configurable via env vars — see `.env.example`.

Large rulesets are **not committed**; the container fetches them itself. To
pull them manually (e.g. for local non-Docker dev, or to force a refresh):

```bash
./scripts/install-yara-rules.sh core        # ~5,100 curated YARA-Forge rules
./scripts/install-sigma-rules.sh hayabusa   # curated, low-FP Sigma rules
docker compose restart backend              # recompile rulesets
```

To force an update on next container start without waiting for the 24h
interval, set `YARA_FORCE_UPDATE=true` / `SIGMA_FORCE_UPDATE=true` in `.env`.

## Development

```bash
# Backend
cd backend
python -m venv venv && source venv/bin/activate   # venv\Scripts\activate on Windows
pip install -r requirements.txt
uvicorn app.main:app --reload

# Frontend
cd frontend
npm install && npm run dev
```

Diagnostics: `./scripts/diagnose.sh` (general) and
`./scripts/diagnose-sigma.sh` (rule loading). Build check: `./scripts/verify-build.sh`.

## Design principles

- **Thin orchestrator** — `orchestrator.py` only sequences calls; all logic
  lives in `services.py` and the engine modules.
- **Plugin-based artifact parsing** — new collectors (MFT, Prefetch, Browser…)
  implement `AnalyzerPlugin` and register in `PluginRegistry`, with zero
  changes to the detection/correlation pipeline.
- **Routing-table detection** — each detector is one file exposing
  `detect_*(engine, key, rows)`, wired in via a single `register_route(...)`
  call. `base.py`'s dispatch loop never changes as detectors are added.
- **Unified `Artifact` model** — every parser emits the same normalized shape,
  so correlation and Sigma evaluation don't special-case data sources.
- **Cloud-boundary anonymization only** — see the note at the top.

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add a detector, a plugin,
or an API route.
