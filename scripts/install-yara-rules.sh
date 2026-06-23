#!/usr/bin/env bash
#
# install-yara-rules.sh — fetch curated YARA rules into ./backend/yara_rules/
#
# Sources (in order of relevance to this platform):
#   1. YARA-Forge (YARAHQ) — automated aggregator of 45+ vetted YARA rule
#      repos, quality-scored and packaged into core/extended/full sets.
#      Same idea as Hayabusa for Sigma: curated, low-FP, ready to use.
#      Weekly auto-published releases. Best default for us.
#   2. Neo23x0/signature-base (Florian Roth) — the frequently-updated
#      source behind much of YARA-Forge; strong webshell/APT coverage.
#
# YARA-Forge packages (pick ONE based on FP tolerance):
#   core     ~5,100 rules  — high accuracy, low false positives (RECOMMENDED)
#   extended ~10,700 rules — broader coverage, some more false positives
#   full     ~11,700 rules — maximum coverage, expect more false positives
#
# Usage:
#   ./install-yara-rules.sh core          # recommended — high-confidence set
#   ./install-yara-rules.sh extended      # broader threat-hunting set
#   ./install-yara-rules.sh full          # everything (noisiest)
#   ./install-yara-rules.sh signature-base # Florian Roth's signature-base
#   ./install-yara-rules.sh               # defaults to core
#
# After running, restart the backend so it recompiles the new ruleset:
#   docker compose restart backend
#

set -euo pipefail

GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${BLUE}ℹ${NC}  $*"; }
ok()    { echo -e "${GREEN}✓${NC}  $*"; }
warn()  { echo -e "${YELLOW}⚠${NC}  $*"; }
err()   { echo -e "${RED}✗${NC}  $*"; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RULES_DIR="$REPO_ROOT/backend/yara_rules"
SOURCE="${1:-core}"

mkdir -p "$RULES_DIR"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

count_rules() {
    # Count 'rule X {' definitions across all .yar/.yara files
    grep -rhoE '^[[:space:]]*rule[[:space:]]+[A-Za-z0-9_]+' "$RULES_DIR" 2>/dev/null | wc -l | tr -d ' '
}

# Preserve our hand-written starter rules across re-installs — they're not
# part of any downloaded package, so a naive overwrite would lose them.
preserve_starter() {
    if [ -f "$RULES_DIR/starter_rules.yar" ]; then
        cp "$RULES_DIR/starter_rules.yar" "$TMP/starter_rules.yar.keep"
    fi
}
restore_starter() {
    if [ -f "$TMP/starter_rules.yar.keep" ]; then
        cp "$TMP/starter_rules.yar.keep" "$RULES_DIR/starter_rules.yar"
        ok "Preserved hand-written starter_rules.yar"
    fi
}

install_yara_forge() {
    local package="$1"
    info "Fetching latest YARA-Forge release metadata (package: $package)..."

    # The GitHub releases API gives us the latest release's assets. YARA-Forge
    # names assets like 'yara-forge-rules-<package>.zip'. We resolve the
    # download URL dynamically so we always get the newest weekly release.
    local api="https://api.github.com/repos/YARAHQ/yara-forge/releases/latest"
    local asset_url

    asset_url=$(curl -fsSL "$api" \
        | grep -oE "https://[^\"]*yara-forge-rules-${package}\.zip" \
        | head -1)

    if [ -z "$asset_url" ]; then
        err "Could not find a '${package}' package asset in the latest release."
        err "Check available packages at: https://github.com/YARAHQ/yara-forge/releases"
        exit 1
    fi

    info "Downloading: $asset_url"
    curl -fsSL "$asset_url" -o "$TMP/yara-forge.zip"

    info "Extracting..."
    unzip -q -o "$TMP/yara-forge.zip" -d "$TMP/extracted"

    # The zip contains a single combined .yar file (packages/<package>/...).
    # Find it and install it under a clear name.
    local found
    found=$(find "$TMP/extracted" -name "*.yar" -o -name "*.yara" | head -5)
    if [ -z "$found" ]; then
        err "No .yar files found in the downloaded package."
        exit 1
    fi

    preserve_starter
    # Clear previously-installed forge rules (but not our starter file —
    # restored below) so switching core->extended doesn't leave stale rules.
    find "$RULES_DIR" -name "yara-forge-*.yar" -delete 2>/dev/null || true

    local n=0
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        cp "$f" "$RULES_DIR/yara-forge-${package}-$(basename "$f")"
        n=$((n+1))
    done <<< "$(find "$TMP/extracted" \( -name "*.yar" -o -name "*.yara" \))"

    restore_starter
    ok "Installed YARA-Forge '$package' package ($n file(s))"
}

install_signature_base() {
    info "Cloning Neo23x0/signature-base (Florian Roth)..."
    cd "$TMP"
    # Shallow clone — we only need current rules, not history.
    git clone --depth 1 https://github.com/Neo23x0/signature-base.git 2>/dev/null

    preserve_starter
    find "$RULES_DIR" -name "sigbase-*.yar" -delete 2>/dev/null || true

    local n=0
    # signature-base keeps YARA rules under yara/ ; some rules reference
    # external variables (filename, filepath) that need providing at scan
    # time. The scanner skips un-compilable files gracefully, so copying
    # all of them is safe.
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        cp "$f" "$RULES_DIR/sigbase-$(basename "$f")"
        n=$((n+1))
    done <<< "$(find signature-base/yara -name '*.yar')"

    restore_starter
    ok "Installed signature-base ($n rule file(s))"
    warn "Note: some signature-base rules use external variables and may be"
    warn "skipped by the scanner. That's expected — the rest still work."
}

echo ""
info "YARA rules installer — target: $RULES_DIR"
echo ""

case "$SOURCE" in
    core|extended|full)
        install_yara_forge "$SOURCE"
        ;;
    signature-base|sigbase)
        install_signature_base
        ;;
    *)
        err "Unknown source: $SOURCE"
        echo "Valid options: core | extended | full | signature-base"
        exit 1
        ;;
esac

echo ""
ok "Done. Total rules now in $RULES_DIR: $(count_rules)"
echo ""
info "Restart the backend to recompile the new ruleset:"
echo "    docker compose restart backend"
echo ""
