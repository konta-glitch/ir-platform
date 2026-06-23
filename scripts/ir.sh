#!/usr/bin/env bash
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; PURPLE='\033[0;35m'; CYAN='\033[0;36m'
BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

info()  { echo -e "${BLUE}ℹ${NC}  $*"; }
ok()    { echo -e "${GREEN}✓${NC}  $*"; }
warn()  { echo -e "${YELLOW}⚠${NC}  $*"; }
fail()  { echo -e "${RED}✗${NC}  $*"; }

cd "$(cd "$(dirname "$0")" && pwd)"
API="http://localhost:8080/api"

get_lm_model() {
    curl -s --connect-timeout 3 http://localhost:1234/v1/models 2>/dev/null | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',[{}])[0].get('id',''))" 2>/dev/null
}

cmd_start() {
    info "Starting (building latest code)..."
    local model; model=$(get_lm_model)
    [ -n "$model" ] && ok "LM Studio: $model" || warn "LM Studio not running"
    docker compose up -d --build
    info "Waiting for backend to come up..."
    local tries=0
    while [ $tries -lt 20 ]; do
        if curl -s --connect-timeout 2 "$API/health" >/dev/null 2>&1; then
            ok "Backend is up — Dashboard: http://localhost:3000"
            return 0
        fi
        sleep 1; tries=$((tries+1))
    done
    warn "Backend did not respond after 20s. Check logs:"
    echo "    ./ir.sh logs backend"
    echo "    ./diagnose.sh"
}

cmd_stop() { docker compose down; ok "Stopped"; }
cmd_restart() { docker compose restart; ok "Restarted"; }

cmd_status() {
    echo -e "${BOLD}Containers${NC}"
    docker compose ps 2>/dev/null
    echo ""
    local h; h=$(curl -s --connect-timeout 3 "$API/health" 2>/dev/null)
    if [ -n "$h" ]; then
        echo -e "${BOLD}Health${NC}"
        local lm cl model
        lm=$(echo "$h" | python3 -c "import sys,json; print(json.load(sys.stdin).get('lm_studio_reachable',False))" 2>/dev/null)
        cl=$(echo "$h" | python3 -c "import sys,json; print(json.load(sys.stdin).get('claude_api_configured',False))" 2>/dev/null)
        model=$(echo "$h" | python3 -c "import sys,json; v=json.load(sys.stdin).get('lm_studio_model',''); print(v if v else '')" 2>/dev/null)
        [ "$lm" = "True" ] && ok "LM Studio: ${model:-connected}" || warn "LM Studio: not connected"
        [ "$cl" = "True" ] && ok "Claude API: configured (standby)" || info "Claude API: not configured (optional)"
    else
        warn "Backend not responding"
    fi
}

cmd_health() {
    echo -e "${BOLD}Health Check${NC}"
    echo ""
    local model; model=$(get_lm_model)
    [ -n "$model" ] && ok "LM Studio: $model" || fail "LM Studio: not reachable"
    curl -s --connect-timeout 3 http://localhost:8080/api/health &>/dev/null && ok "Backend: http://localhost:8080" || fail "Backend: not reachable"
    curl -s --connect-timeout 3 http://localhost:3000 &>/dev/null && ok "Dashboard: http://localhost:3000" || fail "Dashboard: not reachable"
    echo ""
    docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" $(docker compose ps -q 2>/dev/null) 2>/dev/null || true
}

cmd_logs() { docker compose logs -f --tail ${2:-50} ${1:+$1}; }
cmd_shell() { docker compose exec backend bash || docker compose exec backend sh; }

cmd_analyze() {
    local data=""
    if [ -n "${1:-}" ] && [ -f "$1" ]; then
        data=$(cat "$1"); info "Analyzing: $1"
    else
        echo -e "${BOLD}Paste forensic data${NC} ${DIM}(Ctrl+D when done):${NC}"; data=$(cat)
    fi
    [ -z "$data" ] && { fail "No data"; return 1; }
    echo ""; info "Anonymizing + analyzing..."
    python3 -c "
import json, sys, urllib.request
payload = json.dumps({'title':'CLI analysis','raw_data':sys.stdin.read(),'data_type':'mixed','allow_cloud':False}).encode()
req = urllib.request.Request('$API/analyze', data=payload, headers={'Content-Type':'application/json'})
try:
    with urllib.request.urlopen(req, timeout=300) as r:
        d = json.loads(r.read())
        a, s = d.get('analysis',{}), d.get('stats',{})
        print(f\"\033[1mSeverity:\033[0m {a.get('severity','?')}\")
        print(f\"\033[1mConfidence:\033[0m {s.get('local_analysis_confidence',0):.0%}\")
        print(f\"\033[1mPII redacted:\033[0m {s.get('pii_items_redacted',0)}\")
        print(f\"\n\033[1mSummary:\033[0m\n  {a.get('summary','')}\")
        iocs = a.get('iocs',[])
        if iocs:
            print(f\"\n\033[1mIOCs ({len(iocs)}):\033[0m\")
            for i in iocs: print(f\"  {'🔴' if i.get('malicious') else '○'} [{i.get('type','')}] {i.get('value','')} ({i.get('confidence',0):.0%})\")
        techs = a.get('mitre_techniques',[])
        if techs:
            print(f\"\n\033[1mMITRE ({len(techs)}):\033[0m\")
            for t in techs: print(f\"  • {t.get('technique_id','')} {t.get('technique_name','')} [{t.get('tactic','')}]\")
        recs = a.get('recommendations',[])
        if recs:
            print(f\"\n\033[1mRecommendations:\033[0m\")
            for n,r in enumerate(recs,1): print(f\"  {n}. {r}\")
except Exception as e: print(f'Error: {e}')
" <<< "$data"
}

cmd_model() {
    local model; model=$(get_lm_model)
    [ -n "$model" ] && ok "Loaded: $model" || { fail "LM Studio not reachable"; return 1; }
    local env_model; env_model=$(grep "LM_STUDIO_MODEL" .env 2>/dev/null | cut -d= -f2)
    [ -n "$env_model" ] && [ "$env_model" = "$model" ] && ok "Matches .env" || warn ".env: $env_model"
}

cmd_update() {
    docker compose down
    docker compose build
    SIGMA_FORCE_UPDATE=true docker compose up -d
    ok "Updated (Sigma rules refreshing in background)"
}

cmd_sigma() {
    case "${1:-status}" in
        update)
            info "Forcing Hayabusa Sigma rule update..."
            docker compose restart backend
            sleep 3
            curl -s -X POST http://localhost:8080/api/sigma/reload >/dev/null 2>&1 && ok "Reload triggered"
            ;;
        *)
            local r; r=$(curl -s http://localhost:8080/api/sigma/rules 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('rule_count',0))" 2>/dev/null)
            ok "Loaded Sigma rules: ${r:-unknown}"
            ;;
    esac
}
cmd_reset() {
    echo -en "${RED}?${NC}  Type 'RESET' to confirm: "; read -r c
    [ "$c" = "RESET" ] && { docker compose down -v; rm -rf data/* exports/*; ok "Reset"; } || info "Cancelled"
}

cmd_help() {
    echo -e "${BOLD}IR Platform${NC}"
    echo ""
    echo -e "  ${GREEN}start${NC}           Start services"
    echo -e "  ${GREEN}stop${NC}            Stop services"
    echo -e "  ${GREEN}restart${NC}         Restart"
    echo -e "  ${GREEN}status${NC}          Status + health"
    echo -e "  ${GREEN}health${NC}          Detailed health"
    echo -e "  ${CYAN}logs${NC} [svc]      Follow logs"
    echo -e "  ${CYAN}shell${NC}           Backend shell"
    echo -e "  ${PURPLE}analyze${NC} [file]  Analyze data locally"
    echo -e "  ${PURPLE}model${NC}           LM Studio model info"
    echo -e "  ${YELLOW}update${NC}          Rebuild + refresh Sigma rules"
    echo -e "  ${PURPLE}sigma${NC} [update]   Show/update Sigma rule count"
    echo -e "  ${RED}reset${NC}           Delete all data"
}

case "${1:-help}" in
    start) cmd_start;; stop) cmd_stop;; restart) cmd_restart;;
    status) cmd_status;; health) cmd_health;; logs) cmd_logs "${2:-}" "${3:-}";;
    shell) cmd_shell;; analyze) cmd_analyze "${2:-}";; model) cmd_model;;
    update) cmd_update;; reset) cmd_reset;; sigma) cmd_sigma "${2:-}";; diagnose) ./diagnose.sh;; help|--help|-h) cmd_help;;
    *) fail "Unknown: $1"; cmd_help; exit 1;;
esac
