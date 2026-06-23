# IR Platform — Step-by-Step Setup Guide

Complete setup guide for the local-first Incident Response platform on MacBook M4 Pro 48GB.

---

## Prerequisites Checklist

Before starting, make sure you have:

- MacBook with Apple Silicon (M4 Pro 48GB recommended, M1/M2/M3 with ≥32GB works)
- macOS Sonoma 14+ or Sequoia 15+
- Administrator access on the Mac
- Velociraptor server already deployed with endpoints reporting to it
- Anthropic API key (for optional cloud escalation)

---

## Part 1: Install Docker Desktop

Docker Desktop runs the backend (FastAPI) and frontend (React + nginx) containers.

**1.1 Download Docker Desktop**

Go to https://www.docker.com/products/docker-desktop/ and download the
"Apple Silicon" version. Open the .dmg and drag Docker to Applications.

**1.2 Launch and configure**

Open Docker Desktop from Applications. On first launch it will ask for
permissions — accept them.

Open Docker Desktop Settings (gear icon top-right):

- General: enable "Start Docker Desktop when you log in" if you want it always available
- Resources → Advanced:
  - CPUs: 4 (leave the rest for LM Studio)
  - Memory: 8 GB (the LLM runs natively outside Docker, so Docker doesn't need much)
  - Swap: 2 GB
  - Disk image size: 20 GB
- Resources → Network: leave defaults

Click "Apply & Restart".

**1.3 Verify**

Open Terminal and run:

```bash
docker --version
docker compose version
```

Both should return version numbers. If `docker compose` doesn't work, you
may need to enable it in Docker Desktop Settings → General → "Use Docker Compose V2".

---

## Part 2: Install and Configure LM Studio

LM Studio runs the local LLM natively on your Mac (not in Docker).
This gives it direct access to the Apple Silicon Neural Engine and unified memory.

**2.1 Download LM Studio**

Go to https://lmstudio.ai and download the macOS version.
Open the .dmg and drag LM Studio to Applications. Launch it.

**2.2 Download a model**

In LM Studio, go to the Search tab (magnifying glass icon on the left sidebar).

Recommended models for 48GB RAM (pick one):

| Model | Search term | Size | Speed | Quality |
|-------|------------|------|-------|---------|
| Qwen2.5-Coder-14B-Instruct (MLX) | `qwen2.5 coder 14b instruct mlx` | ~16GB | ~30 tok/s | Very good |
| Qwen2.5-14B-Instruct (MLX) | `qwen2.5 14b instruct mlx` | ~16GB | ~30 tok/s | Very good |
| Mistral-Small-24B-Instruct (GGUF Q4) | `mistral small 24b instruct` | ~16GB | ~20 tok/s | Excellent |
| Qwen2.5-32B-Instruct (GGUF Q4) | `qwen2.5 32b instruct` | ~22GB | ~15 tok/s | Excellent |

Choose MLX format when available — it's optimized for Apple Silicon and faster
than GGUF on M-series chips. Qwen2.5-Coder-14B is a great starting pick because
it handles structured JSON output very reliably, which is critical for IR analysis.

Click the download button next to the model. Wait for download to complete
(typically 10-15GB, takes a few minutes).

**2.3 Load the model and start the server**

Go to the **"Developer"** tab in LM Studio (left sidebar, looks like a code
brackets icon or wrench icon).

You'll see the **"Local Server"** section at the top.

1. Click **"+ Load Model"** (blue button, top-right) and select your
   downloaded model from the dropdown
2. Wait for the model to load — status will change to **READY** with a
   green badge, showing the model ID (e.g., `qwen2.5-coder-14b-instruct-mlx`)
3. The server auto-starts — you should see **"Status: Running"** at the top
   and a URL like `http://127.0.0.1:1234`

Configure settings in the right panel:

- **Temperature**: 0 (drag slider all the way left — we want deterministic output)
- **Context Overflow**: "Truncate Middle" (default, good for long forensic data)
- **Structured Output**: leave off (we handle JSON parsing in code)

The "Supported endpoints" section shows three API formats. Our platform uses
the **OpenAI-compatible** format (`/v1/chat/completions`) with automatic
fallback to the LM Studio REST API v1 format.

**2.4 Note the model ID**

The model ID is shown in the green "READY" box. In the screenshot example
it shows `qwen2.5-coder-14b-instruct-mlx`. You need this exact string
for the `.env` file. You can also copy it from the terminal:

```bash
curl http://localhost:1234/v1/models
```

Look for the `"id"` field in the response.

**2.5 Verify the server**

```bash
# Check server is running
curl http://localhost:1234/v1/models

# Test inference
curl http://localhost:1234/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "qwen2.5-coder-14b-instruct-mlx",
    "messages": [{"role": "user", "content": "Say hello in one word"}],
    "max_tokens": 10
  }'
```

You should get a JSON response with the model's reply.

**IMPORTANT**: LM Studio must be running with a model loaded whenever you
use the IR platform. If LM Studio is closed, anonymization and local analysis
will fail.

---

## Part 3: Configure Velociraptor API Access

The IR platform connects to your Velociraptor server's API to collect
forensic artifacts from endpoints.

**3.1 Option A: API key (simpler)**

If your Velociraptor server supports API key authentication:

1. Log into the Velociraptor web UI as admin
2. Go to Server Configuration or API settings
3. Generate an API key
4. Note the API URL (typically `https://your-velo-server:8001`)

You'll put these in the `.env` file later.

**3.2 Option B: API config YAML (standard Velociraptor method)**

This is the standard approach using Velociraptor's gRPC API.

On the Velociraptor server, generate an API client config:

```bash
velociraptor config api_client \
  --name ir-platform \
  --role reader,investigator \
  api_client.yaml
```

Copy the generated `api_client.yaml` to your Mac. You'll place it in
the `data/` directory of the project later.

**3.3 Network connectivity**

Make sure your Mac can reach the Velociraptor server:

```bash
curl -k https://your-velo-server:8001/api/v1/GetServerMonitoringState
```

If the server uses a self-signed certificate (common), the `-k` flag
is needed. The platform handles this automatically.

If the Velociraptor server is on a VPN or internal network, make sure the
VPN is connected before running the platform.

---

## Part 4: Get an Anthropic API Key

Claude is used only for targeted knowledge gap queries (optional but recommended).

**4.1 Create an Anthropic account**

Go to https://console.anthropic.com and create an account (or log in).

**4.2 Generate an API key**

1. Go to https://console.anthropic.com/settings/keys
2. Click "Create Key"
3. Name it "IR Platform"
4. Copy the key (starts with `sk-ant-`)

**4.3 Add credits**

Go to https://console.anthropic.com/settings/billing and add credits.
Typical IR usage costs $0.01-0.05 per incident (5-15 targeted questions).

---

## Part 5: Project Setup

**5.1 Extract the project**

```bash
# Create a directory for the project
mkdir -p ~/Projects
cd ~/Projects

# Extract the archive you downloaded from Claude
tar -xzf ~/Downloads/ir-platform-local-first.tar.gz
cd ir-platform
```

**5.2 Create the environment file**

```bash
cp .env.example .env
```

Now edit `.env` with your actual values:

```bash
nano .env
```

Or open in any text editor. Fill in:

```env
# LM Studio — this should work as-is if LM Studio is on default port
LM_STUDIO_BASE_URL=http://host.docker.internal:1234/v1
LM_STUDIO_MODEL=qwen2.5-coder-14b-instruct-mlx

# Claude API — paste your API key here
ANTHROPIC_API_KEY=sk-ant-api03-YOUR_ACTUAL_KEY_HERE
CLAUDE_MODEL=claude-sonnet-4-20250514

# Velociraptor — update with your server details
VELOCIRAPTOR_API_URL=https://your-velo-server:8001
VELOCIRAPTOR_API_KEY=your-velociraptor-api-key-here
VELOCIRAPTOR_CONFIG_PATH=/app/data/velociraptor_api_config.yaml

# Leave these as-is
LOG_LEVEL=INFO
DATA_DIR=/app/data
EXPORT_DIR=/app/exports
```

**IMPORTANT NOTES:**

- `LM_STUDIO_MODEL` must exactly match the model ID shown in the green
  "READY" box in LM Studio, or from `curl http://localhost:1234/v1/models`.
  Common examples: `qwen2.5-coder-14b-instruct-mlx`,
  `qwen2.5-14b-instruct`, or a full path like
  `lmstudio-community/qwen2.5-14b-instruct-GGUF/qwen2.5-14b-instruct-q6_k.gguf`.

- `host.docker.internal` is a special Docker hostname that resolves to
  your Mac's localhost. This is how the Docker container reaches LM Studio
  running natively on the Mac.

**5.3 Place Velociraptor config (if using Option B)**

If you have an `api_client.yaml` from Velociraptor:

```bash
mkdir -p data
cp /path/to/api_client.yaml data/velociraptor_api_config.yaml
```

**5.4 Create required directories**

```bash
mkdir -p data exports
```

---

## Part 6: Build and Launch

**6.1 Make sure prerequisites are running**

Before building, verify:

```bash
# Docker is running?
docker info > /dev/null 2>&1 && echo "Docker: OK" || echo "Docker: NOT RUNNING"

# LM Studio is running with a model?
curl -s http://localhost:1234/v1/models | grep -q "id" && echo "LM Studio: OK" || echo "LM Studio: NOT RUNNING"
```

Both should say OK.

**6.2 Build and start the containers**

```bash
cd ~/Projects/ir-platform
docker compose up --build
```

First build takes 2-5 minutes (downloading Python packages, building React app).
Subsequent starts are much faster.

You'll see logs from both containers. Look for:

```
ir-backend  | INFO:     Uvicorn running on http://0.0.0.0:8000
ir-backend  | INFO:     IR Platform starting (local-first mode)
ir-backend  | INFO:     LM Studio model: qwen2.5-14b-instruct
ir-frontend | ... ready ...
```

**6.3 Run in background (optional)**

If you don't want logs in your terminal:

```bash
docker compose up --build -d
```

View logs later with:

```bash
docker compose logs -f          # all services
docker compose logs -f backend  # just the API
```

**6.4 Verify everything is connected**

```bash
curl http://localhost:8000/api/health | python3 -m json.tool
```

Expected output:

```json
{
    "status": "ok",
    "lm_studio_reachable": true,
    "lm_studio_model": "qwen2.5-14b-instruct",
    "velociraptor_reachable": true,
    "claude_api_configured": true
}
```

If `lm_studio_reachable` is false, check that LM Studio's server is
running and that a model is loaded.

If `velociraptor_reachable` is false, check your VPN, server URL, and API key.

If `claude_api_configured` is false, check your ANTHROPIC_API_KEY in `.env`.

---

## Part 7: Open the Dashboard

Open your browser and go to:

```
http://localhost:3000
```

You should see the IR Platform dashboard with three status indicators
at the top (LM Studio, Velociraptor, Claude API).

---

## Part 8: First Test Run

**8.1 Find a Velociraptor client ID**

In the Velociraptor web UI, navigate to any endpoint and copy its client ID
(looks like `C.1234567890abcdef`).

Or use the API:

```bash
curl http://localhost:8000/api/velociraptor/clients | python3 -m json.tool
```

**8.2 Run the full pipeline from the dashboard**

1. Go to the "Pipeline" tab
2. Enter the client ID
3. Enter a title like "Test run"
4. Select artifacts: processes, network
5. Decide on cloud settings:
   - Toggle "Cloud Escalation" on or off
   - Adjust the confidence threshold slider (default 70%)
6. Click "Run"

The pipeline will:
- Collect artifacts from the endpoint via Velociraptor
- Anonymize all PII locally using LM Studio
- Analyze the data locally using LM Studio
- Show you the results (IOCs, MITRE techniques, timeline, recommendations)
- If cloud is enabled and confidence is low, escalate specific questions to Claude

**8.3 Test with manual data**

If Velociraptor isn't set up yet, you can test with the "Manual" tab.
Paste sample forensic data (a process list, netstat output, etc.) and
click "Analyze".

Example test data you can paste:

```json
[
  {"pid": 4812, "name": "powershell.exe",
   "cmdline": "powershell -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0",
   "user": "CORP\\jsmith", "ppid": 1024,
   "hash_sha256": "a1b2c3d4e5f6..."},
  {"pid": 5120, "name": "svchost.exe",
   "cmdline": "svchost.exe -k netsvcs",
   "user": "SYSTEM", "ppid": 672,
   "connections": [
     {"remote_ip": "185.220.101.45", "remote_port": 443, "state": "ESTABLISHED"},
     {"remote_ip": "192.168.1.1", "remote_port": 53, "state": "ESTABLISHED"}
   ]}
]
```

---

## Part 9: Daily Operations

**Starting the platform:**

```bash
# 1. Make sure LM Studio is open with server running
# 2. Start Docker containers
cd ~/Projects/ir-platform
docker compose up -d
# 3. Open http://localhost:3000
```

**Stopping the platform:**

```bash
docker compose down
```

**Updating the platform:**

If you receive a new version:

```bash
docker compose down
# Extract new files
tar -xzf ir-platform-local-first-v2.tar.gz
cd ir-platform
docker compose up --build -d
```

**Changing the LLM model:**

1. In LM Studio, click "Eject" on the current model, then "+ Load Model" for a new one
2. Check the model ID: `curl http://localhost:1234/v1/models`
3. Update `LM_STUDIO_MODEL` in `.env`
4. Restart the backend: `docker compose restart backend`

---

## Troubleshooting

**"LM Studio not reachable" in health check**

- Is LM Studio open? Is the server started (Developer tab → Start Server)?
- Is a model loaded? The server needs a model to respond.
- Check the port: `curl http://localhost:1234/v1/models`
- If you changed the port in LM Studio, update `LM_STUDIO_BASE_URL` in `.env`

**"Velociraptor not reachable"**

- Is the Velociraptor server running?
- Is your VPN connected (if needed)?
- Check the URL: `curl -k https://your-velo-server:8001`
- Verify your API key is correct
- Check Docker can reach external hosts: `docker exec ir-backend curl -k https://your-velo-server:8001`

**Docker build fails on npm install**

- Docker needs internet access for npm packages
- Check Docker's DNS: Docker Desktop → Settings → Resources → Network
- Try: `docker compose build --no-cache`

**Analysis is slow**

- Local LLM analysis takes 30-120 seconds depending on data size and model
- Larger models (24B, 32B) are slower but more accurate
- Reduce data volume by selecting fewer artifact types
- Make sure no other heavy apps are competing for RAM

**"Cannot connect to Docker daemon"**

- Open Docker Desktop from Applications
- Wait for the Docker icon in the menu bar to show "Docker Desktop is running"
- Then retry `docker compose up`

**Port conflicts**

If port 8000 or 3000 is already in use:

```bash
# Check what's using the port
lsof -i :8000
lsof -i :3000

# Change ports in docker-compose.yml if needed
# e.g., "9000:8000" maps host port 9000 to container port 8000
```

**Container logs**

```bash
# All logs
docker compose logs

# Follow backend logs in real-time
docker compose logs -f backend

# Last 100 lines
docker compose logs --tail 100 backend
```

---

## Security Reminders

- The `.env` file contains your API keys. Never commit it to git.
  Add `.env` to `.gitignore`.
- The local LLM processes ALL data before anything leaves your machine.
- Claude only receives anonymized, targeted questions — never raw forensic data.
- De-anonymization mappings are stored in memory only (lost on restart).
  For persistence, you would need to add a database (future enhancement).
- The Velociraptor connection uses TLS. In production, pin the certificate
  instead of accepting self-signed certs.
