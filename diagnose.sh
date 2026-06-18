#!/usr/bin/env bash
#
# diagnose.sh — pinpoints why the platform isn't responding.
# Run this from the project root: ./diagnose.sh
#

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓${NC} $*"; }
bad()  { echo -e "${RED}✗${NC} $*"; }
warn() { echo -e "${YELLOW}⚠${NC} $*"; }
info() { echo -e "${BLUE}ℹ${NC} $*"; }

echo ""
echo "════════════════════════════════════════════"
echo "  IR Platform Diagnostics"
echo "════════════════════════════════════════════"
echo ""

# 1. Docker running?
info "1. Checking Docker..."
if docker info >/dev/null 2>&1; then
    ok "Docker is running"
else
    bad "Docker is NOT running — start Docker Desktop first"
    exit 1
fi

# 2. Containers up?
info "2. Checking containers..."
BACKEND_STATE=$(docker compose ps --format json 2>/dev/null | python3 -c "
import sys, json
try:
    for line in sys.stdin:
        c = json.loads(line)
        if 'backend' in c.get('Service',''):
            print(c.get('State','unknown'))
            break
    else:
        print('not_found')
except: print('parse_error')
" 2>/dev/null)

if [ "$BACKEND_STATE" = "running" ]; then
    ok "Backend container is running"
elif [ "$BACKEND_STATE" = "not_found" ]; then
    bad "Backend container doesn't exist — run: docker compose up -d --build"
    exit 1
else
    bad "Backend container state: $BACKEND_STATE"
    warn "It may be crash-looping. Checking logs below..."
fi

# 3. Recent backend logs — look for the real error
info "3. Last 30 backend log lines (looking for errors)..."
echo "────────────────────────────────────────────"
docker compose logs --tail=30 backend 2>/dev/null | grep -iE "error|traceback|exception|failed|cannot|refused|modulenotfound|importerror" || echo "(no obvious errors in recent logs)"
echo "────────────────────────────────────────────"

# 4. Is the API actually responding?
info "4. Testing API health endpoint..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://localhost:8080/api/health 2>/dev/null)
if [ "$HTTP_CODE" = "200" ]; then
    ok "API responds (HTTP 200)"
    curl -s --max-time 5 http://localhost:8080/api/health | python3 -m json.tool 2>/dev/null | head -10
elif [ "$HTTP_CODE" = "000" ]; then
    bad "API not reachable — backend isn't listening on port 8080"
    warn "Most likely the backend crashed on startup. Full logs:"
    echo "    docker compose logs backend | tail -50"
else
    warn "API returned HTTP $HTTP_CODE"
fi

# 5. Frontend reachable?
info "5. Testing frontend..."
FE_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://localhost:3000 2>/dev/null)
if [ "$FE_CODE" = "200" ]; then
    ok "Frontend responds (HTTP 200)"
else
    warn "Frontend returned HTTP $FE_CODE (may still be starting)"
fi

# 6. LM Studio reachable from host?
info "6. Testing LM Studio (host:1234)..."
LM_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://localhost:1234/v1/models 2>/dev/null)
if [ "$LM_CODE" = "200" ]; then
    ok "LM Studio is reachable"
    MODEL=$(curl -s --max-time 5 http://localhost:1234/v1/models | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data'][0]['id'] if d.get('data') else 'none')" 2>/dev/null)
    info "   Loaded model: $MODEL"
else
    bad "LM Studio NOT reachable on port 1234"
    warn "Start LM Studio and load a model, then enable the local server"
fi

# 7. Check .env model string
info "7. Checking .env configuration..."
if [ -f .env ]; then
    if grep -q "claude-sonnet-4-20250514" .env 2>/dev/null; then
        bad "Stale CLAUDE_MODEL in .env (claude-sonnet-4-20250514)"
        warn "Fix: sed -i '' 's/claude-sonnet-4-20250514/claude-sonnet-4-6/' .env"
    else
        ok ".env model string looks current"
    fi
    if grep -q "ANTHROPIC_API_KEY=sk-" .env 2>/dev/null; then
        ok "Anthropic API key is set"
    else
        warn "No Anthropic API key (cloud escalation will be unavailable — local still works)"
    fi
else
    warn ".env not found — run ./setup.sh"
fi

echo ""
echo "════════════════════════════════════════════"
echo "  Summary"
echo "════════════════════════════════════════════"
if [ "$HTTP_CODE" = "200" ] && [ "$LM_CODE" = "200" ]; then
    ok "Platform looks healthy. If analysis still fails, run an analysis"
    info "   and watch: docker compose logs -f backend"
elif [ "$HTTP_CODE" != "200" ]; then
    bad "Backend is the problem. Get the full crash reason with:"
    echo "    docker compose logs backend 2>&1 | tail -60"
    echo ""
    info "Common causes:"
    echo "    • Missing dependency → rebuild: docker compose build --no-cache backend"
    echo "    • Port 8080 already in use → lsof -i :8080"
    echo "    • Code error → the traceback will show the file and line"
fi
echo ""
