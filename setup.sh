#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; PURPLE='\033[0;35m'; CYAN='\033[0;36m'
BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

info()  { echo -e "${BLUE}ℹ${NC}  $*"; }
ok()    { echo -e "${GREEN}✓${NC}  $*"; }
warn()  { echo -e "${YELLOW}⚠${NC}  $*"; }
fail()  { echo -e "${RED}✗${NC}  $*"; }
step()  { echo -e "\n${PURPLE}━━━ $* ━━━${NC}\n"; }
ask()   { echo -en "${CYAN}?${NC}  $* "; }

json_val() {
    python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    keys = '${1}'.split('.')
    v = d
    for k in keys:
        if isinstance(v, list) and k.isdigit(): v = v[int(k)]
        elif isinstance(v, dict): v = v.get(k)
        else: v = None; break
    if v is not None: print(v)
except: pass
" 2>/dev/null
}

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

echo -e "
${BOLD}╔══════════════════════════════════════════╗
║         IR Platform Setup                ║
║   Local-First Incident Response          ║
╚══════════════════════════════════════════╝${NC}
${DIM}LM Studio + Claude (standby) + Standalone Collectors${NC}
"

step "Step 1/5 — Checking prerequisites"

ERRORS=0

command -v python3 &>/dev/null && ok "Python3" || { fail "Python3 not found"; ERRORS=$((ERRORS+1)); }

if command -v docker &>/dev/null; then
    ok "Docker installed"
else
    fail "Docker not found — install: https://docker.com/products/docker-desktop/"
    ERRORS=$((ERRORS+1))
fi

docker info &>/dev/null && ok "Docker running" || { fail "Docker not running — open Docker Desktop"; ERRORS=$((ERRORS+1)); }
docker compose version &>/dev/null && ok "Docker Compose" || { fail "Docker Compose missing"; ERRORS=$((ERRORS+1)); }

# LM Studio
LM_MODEL=""
lm_resp=$(curl -s --connect-timeout 3 http://localhost:1234/v1/models 2>/dev/null) || true
if [ -n "$lm_resp" ]; then
    LM_MODEL=$(echo "$lm_resp" | json_val "data.0.id")
    [ -n "$LM_MODEL" ] && ok "LM Studio: ${BOLD}${LM_MODEL}${NC}" || warn "LM Studio running but no model loaded"
else
    warn "LM Studio not reachable (port 1234) — start it before using"
fi

[ $ERRORS -gt 0 ] && { fail "${ERRORS} issue(s). Fix and re-run."; exit 1; }

step "Step 2/5 — Checking ports"

for p in 8080 3000; do
    if command -v lsof &>/dev/null && lsof -i :"$p" &>/dev/null; then
        warn "Port $p in use"
    else
        ok "Port $p free"
    fi
done

step "Step 3/5 — Configuring"

SKIP_ENV=false
if [ -f .env ]; then
    # Auto-correct known-stale model strings in existing .env
    if grep -q "claude-sonnet-4-20250514\|claude-3-5-sonnet" .env 2>/dev/null; then
        sed -i.bak 's/CLAUDE_MODEL=claude-sonnet-4-20250514/CLAUDE_MODEL=claude-sonnet-4-6/; s/CLAUDE_MODEL=claude-3-5-sonnet.*/CLAUDE_MODEL=claude-sonnet-4-6/' .env
        ok "Updated stale CLAUDE_MODEL to claude-sonnet-4-6"
    fi
    ask "Existing .env found. Reconfigure? [y/N]"
    read -r ans
    [[ "$ans" =~ ^[Yy] ]] || SKIP_ENV=true
fi

if [ "$SKIP_ENV" = false ]; then
    LM_STUDIO_MODEL="${LM_MODEL:-qwen2.5-coder-14b-instruct-mlx}"
    if [ -n "$LM_MODEL" ]; then
        ok "Model auto-detected: $LM_STUDIO_MODEL"
    else
        ask "LM Studio model name:"
        read -r LM_STUDIO_MODEL
        LM_STUDIO_MODEL=${LM_STUDIO_MODEL:-"qwen2.5-coder-14b-instruct-mlx"}
    fi

    echo ""
    ask "Anthropic API key (Enter to skip):"
    read -r ANTHROPIC_KEY

    cat > .env << ENVEOF
LM_STUDIO_BASE_URL=http://host.docker.internal:1234/v1
LM_STUDIO_MODEL=${LM_STUDIO_MODEL}
ANTHROPIC_API_KEY=${ANTHROPIC_KEY:-}
CLAUDE_MODEL=claude-sonnet-4-6
LOG_LEVEL=INFO
DATA_DIR=/app/data
EXPORT_DIR=/app/exports
ENVEOF
    ok ".env configured"
fi

mkdir -p data exports images collections sigma_rules

step "Step 4/5 — Building"

info "First build takes 2-3 minutes..."
docker compose build 2>&1 | tail -3
ok "Built"

step "Step 5/5 — Launching"

docker compose down 2>/dev/null || true
docker compose up -d
ok "Started"

echo ""
info "Waiting for backend..."
for i in $(seq 1 30); do
    curl -s --connect-timeout 2 http://localhost:8080/api/health &>/dev/null && break
    sleep 2
done

HEALTH=$(curl -s http://localhost:8080/api/health 2>/dev/null || echo "{}")
lm_ok=$(echo "$HEALTH" | python3 -c "import sys,json; print(json.load(sys.stdin).get('lm_studio_reachable',False))" 2>/dev/null)
cl_ok=$(echo "$HEALTH" | python3 -c "import sys,json; print(json.load(sys.stdin).get('claude_api_configured',False))" 2>/dev/null)

[ "$lm_ok" = "True" ] && ok "LM Studio connected" || warn "LM Studio not connected"
[ "$cl_ok" = "True" ] && ok "Claude API configured" || info "Claude API not configured (optional)"

echo ""
echo -e "${GREEN}${BOLD}Setup complete!${NC}"
echo ""
echo -e "  ${BOLD}Dashboard${NC}    http://localhost:3000"
echo -e "  ${BOLD}API docs${NC}     http://localhost:8080/docs"
echo ""
echo -e "  ${DIM}./ir.sh status | start | stop | logs | analyze${NC}"
echo ""

if command -v open &>/dev/null; then
    ask "Open dashboard? [Y/n]"
    read -r ans
    [[ "$ans" =~ ^[Nn] ]] || open "http://localhost:3000"
fi
