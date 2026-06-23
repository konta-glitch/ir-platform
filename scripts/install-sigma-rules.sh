#!/usr/bin/env bash
#
# install-sigma-rules.sh — fetch curated detection rules into ./sigma_rules/
#
# Sources (in order of relevance to this platform):
#   1. Yamato-Security/hayabusa-rules — curated, de-abstracted, low-FP,
#      works on built-in Windows logs (not just Sysmon). Best for us.
#   2. SigmaHQ/sigma — the upstream community ruleset (broader, more abstract).
#
# Usage:
#   ./install-sigma-rules.sh hayabusa     # recommended — curated set
#   ./install-sigma-rules.sh sigmahq      # full upstream community set
#   ./install-sigma-rules.sh both         # everything
#   ./install-sigma-rules.sh              # defaults to hayabusa
#

set -euo pipefail

GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${BLUE}ℹ${NC}  $*"; }
ok()    { echo -e "${GREEN}✓${NC}  $*"; }
warn()  { echo -e "${YELLOW}⚠${NC}  $*"; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RULES_DIR="$REPO_ROOT/sigma_rules"
SOURCE="${1:-hayabusa}"

mkdir -p "$RULES_DIR"
cd "$RULES_DIR"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

count_rules() {
    find "$RULES_DIR" -name "*.yml" 2>/dev/null | wc -l | tr -d ' '
}

install_hayabusa() {
    info "Downloading Yamato-Security/hayabusa-rules (curated, low false-positive)..."
    cd "$TMP"
    if command -v git &>/dev/null; then
        git clone --depth 1 https://github.com/Yamato-Security/hayabusa-rules.git hr 2>&1 | tail -1
    else
        # Fallback: download tarball
        info "git not found, downloading tarball..."
        curl -sL https://github.com/Yamato-Security/hayabusa-rules/archive/refs/heads/main.tar.gz -o hr.tar.gz
        mkdir -p hr && tar -xzf hr.tar.gz -C hr --strip-components=1
    fi

    # Copy the most relevant rule categories for offline triage.
    # Hayabusa structures rules under sigma/ (converted) and hayabusa/ (native).
    # We want the sigma/ ones since our engine speaks Sigma.
    local dest="$RULES_DIR/hayabusa"
    mkdir -p "$dest"

    local copied=0
    for category in \
        "sigma/builtin" \
        "sigma/sysmon/process_creation" \
        "sigma/sysmon/registry" \
        "sigma/sysmon/network_connection" \
        "hayabusa/builtin" \
        "hayabusa/sysmon"
    do
        if [ -d "$TMP/hr/$category" ]; then
            find "$TMP/hr/$category" -name "*.yml" -exec cp {} "$dest/" \; 2>/dev/null || true
            local n=$(find "$TMP/hr/$category" -name "*.yml" 2>/dev/null | wc -l | tr -d ' ')
            [ "$n" -gt 0 ] && info "  $category: $n rules"
        fi
    done

    # If the structure is different, grab all yml under rules/
    if [ -d "$TMP/hr/rules" ]; then
        find "$TMP/hr/rules" -name "*.yml" -exec cp {} "$dest/" \; 2>/dev/null || true
    fi
    # Or just everything if structure unknown
    if [ "$(find "$dest" -name '*.yml' | wc -l)" -eq 0 ]; then
        warn "Standard paths empty, copying all .yml files..."
        find "$TMP/hr" -name "*.yml" -exec cp {} "$dest/" \; 2>/dev/null || true
    fi

    ok "Hayabusa rules installed to $dest"
}

install_sigmahq() {
    info "Downloading SigmaHQ/sigma (full community ruleset)..."
    cd "$TMP"
    if command -v git &>/dev/null; then
        git clone --depth 1 https://github.com/SigmaHQ/sigma.git sq 2>&1 | tail -1
    else
        curl -sL https://github.com/SigmaHQ/sigma/archive/refs/heads/master.tar.gz -o sq.tar.gz
        mkdir -p sq && tar -xzf sq.tar.gz -C sq --strip-components=1
    fi

    local dest="$RULES_DIR/sigmahq"
    mkdir -p "$dest"

    # Windows rules are most relevant for our collectors
    for category in \
        "rules/windows/process_creation" \
        "rules/windows/registry" \
        "rules/windows/network_connection" \
        "rules/windows/builtin/security" \
        "rules/windows/builtin/system" \
        "rules/windows/powershell" \
        "rules/windows/file"
    do
        if [ -d "$TMP/sq/$category" ]; then
            find "$TMP/sq/$category" -name "*.yml" -exec cp {} "$dest/" \; 2>/dev/null || true
            local n=$(find "$TMP/sq/$category" -name "*.yml" 2>/dev/null | wc -l | tr -d ' ')
            [ "$n" -gt 0 ] && info "  $category: $n rules"
        fi
    done

    ok "SigmaHQ rules installed to $dest"
}

echo ""
echo "════════════════════════════════════════════"
echo "  Sigma Rules Installer"
echo "════════════════════════════════════════════"
echo ""

BEFORE=$(count_rules)

case "$SOURCE" in
    hayabusa) install_hayabusa ;;
    sigmahq)  install_sigmahq ;;
    both)     install_hayabusa; install_sigmahq ;;
    *) warn "Unknown source '$SOURCE'. Use: hayabusa | sigmahq | both"; exit 1 ;;
esac

AFTER=$(count_rules)
ADDED=$((AFTER - BEFORE))

echo ""
ok "Installed $ADDED new rules (total: $AFTER)"
echo ""
info "Reload rules into the running platform:"
echo "    curl -X POST http://localhost:8080/api/sigma/reload"
echo ""
info "Verify loaded count:"
echo "    curl http://localhost:8080/api/sigma/rules | python3 -m json.tool | head"
echo ""
