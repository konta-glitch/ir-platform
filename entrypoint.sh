#!/usr/bin/env bash
#
# entrypoint.sh — runs on container start (every rebuild/restart).
# Auto-updates detection rules (Hayabusa Sigma + YARA-Forge), then launches
# the API.
#
# Both updates are best-effort and run in the background: if GitHub is
# unreachable, or the rules already exist and are fresh, they skip gracefully
# so startup is NEVER blocked. The platform is functional immediately on first
# boot using the committed starter sets (sigma_rules/builtin_rules.yml and
# backend/yara_rules/starter_rules.yar).
#
# Controlling the updates (env vars, all optional):
#   SIGMA_UPDATE_INTERVAL  seconds between Sigma re-fetches   (default 86400 = 24h)
#   SIGMA_FORCE_UPDATE     "true" forces a Sigma re-fetch now (default false)
#   YARA_UPDATE_INTERVAL   seconds between YARA re-fetches    (default 86400 = 24h)
#   YARA_FORCE_UPDATE      "true" forces a YARA re-fetch now  (default false)
#   YARA_PACKAGE           YARA-Forge package: core|extended|full (default core)
#

set -uo pipefail

# -- Sigma config ------------------------------------------------------------
SIGMA_DIR="/app/sigma_rules"
HAYABUSA_DIR="$SIGMA_DIR/hayabusa"
SIGMA_STAMP="$SIGMA_DIR/.hayabusa_last_update"
SIGMA_MAX_AGE=${SIGMA_UPDATE_INTERVAL:-86400}
SIGMA_FORCE=${SIGMA_FORCE_UPDATE:-false}

# -- YARA config -------------------------------------------------------------
YARA_DIR="/app/yara_rules"
YARA_STAMP="$YARA_DIR/.yara_forge_last_update"
YARA_MAX_AGE=${YARA_UPDATE_INTERVAL:-86400}
YARA_FORCE=${YARA_FORCE_UPDATE:-false}
YARA_PACKAGE=${YARA_PACKAGE:-core}

mkdir -p "$SIGMA_DIR" "$YARA_DIR"

# ============================================================================
#  Sigma (Hayabusa) - unchanged behaviour
# ============================================================================

sigma_should_update() {
    [ "$SIGMA_FORCE" = "true" ] && return 0
    [ ! -d "$HAYABUSA_DIR" ] && return 0
    [ -z "$(find "$HAYABUSA_DIR" -name '*.yml' 2>/dev/null | head -1)" ] && return 0
    if [ -f "$SIGMA_STAMP" ]; then
        local last now age
        last=$(cat "$SIGMA_STAMP" 2>/dev/null || echo 0)
        now=$(date +%s)
        age=$((now - last))
        [ "$age" -gt "$SIGMA_MAX_AGE" ] && return 0
        return 1
    fi
    return 0
}

update_hayabusa() {
    echo "=== Updating Hayabusa Sigma rules ==="
    local tmp
    tmp=$(mktemp -d)

    if timeout 120 git clone --depth 1 \
        https://github.com/Yamato-Security/hayabusa-rules.git "$tmp/hr" 2>&1 | tail -2; then

        mkdir -p "$HAYABUSA_DIR"
        local copied=0
        # Prefer the sigma/ converted rules (work on built-in Windows logs)
        for sub in sigma hayabusa; do
            if [ -d "$tmp/hr/$sub" ]; then
                find "$tmp/hr/$sub" -name "*.yml" -exec cp {} "$HAYABUSA_DIR/" \; 2>/dev/null || true
            fi
        done
        # Fallback: rules/ dir or anything
        [ -d "$tmp/hr/rules" ] && find "$tmp/hr/rules" -name "*.yml" -exec cp {} "$HAYABUSA_DIR/" \; 2>/dev/null || true

        copied=$(find "$HAYABUSA_DIR" -name "*.yml" 2>/dev/null | wc -l | tr -d ' ')
        if [ "$copied" -gt 0 ]; then
            date +%s > "$SIGMA_STAMP"
            echo "=== Hayabusa rules updated: $copied rules ==="
        else
            echo "=== Warning: clone succeeded but no rules copied ==="
        fi
    else
        echo "=== Could not update Hayabusa rules (offline?). Using existing set. ==="
    fi

    rm -rf "$tmp"
}

# ============================================================================
#  YARA (YARA-Forge) - mirrors the Sigma flow
# ============================================================================
#
# We fetch the latest YARA-Forge release's combined .yar for the chosen
# package (core by default). The hand-written starter_rules.yar is always
# preserved - it isn't part of any downloaded package, so a naive refresh
# would lose it. Previously-installed forge files are cleared first so a
# package switch (core -> extended) doesn't leave stale rules behind.

yara_should_update() {
    [ "$YARA_FORCE" = "true" ] && return 0
    # Update if no forge rules present yet (only the committed starter file)
    [ -z "$(find "$YARA_DIR" -name 'yara-forge-*.yar' 2>/dev/null | head -1)" ] && return 0
    if [ -f "$YARA_STAMP" ]; then
        local last now age
        last=$(cat "$YARA_STAMP" 2>/dev/null || echo 0)
        now=$(date +%s)
        age=$((now - last))
        [ "$age" -gt "$YARA_MAX_AGE" ] && return 0
        return 1
    fi
    return 0
}

update_yara_forge() {
    echo "=== Updating YARA-Forge rules (package: $YARA_PACKAGE) ==="
    local tmp
    tmp=$(mktemp -d)

    # Resolve the latest release asset URL dynamically (newest weekly release).
    local api="https://api.github.com/repos/YARAHQ/yara-forge/releases/latest"
    local asset_url
    asset_url=$(timeout 30 curl -fsSL "$api" 2>/dev/null \
        | grep -oE "https://[^\"]*yara-forge-rules-${YARA_PACKAGE}\.zip" \
        | head -1)

    if [ -z "$asset_url" ]; then
        echo "=== Could not resolve YARA-Forge '$YARA_PACKAGE' asset (offline or API limit?). Using existing set. ==="
        rm -rf "$tmp"
        return
    fi

    if timeout 120 curl -fsSL "$asset_url" -o "$tmp/forge.zip" 2>/dev/null \
        && unzip -q -o "$tmp/forge.zip" -d "$tmp/extracted" 2>/dev/null; then

        # Preserve the hand-written starter rules across the refresh.
        local keep=""
        if [ -f "$YARA_DIR/starter_rules.yar" ]; then
            keep="$tmp/starter_rules.yar.keep"
            cp "$YARA_DIR/starter_rules.yar" "$keep"
        fi

        # Clear previously-installed forge rules so a package switch is clean.
        find "$YARA_DIR" -name "yara-forge-*.yar" -delete 2>/dev/null || true

        local copied=0
        while IFS= read -r f; do
            [ -z "$f" ] && continue
            cp "$f" "$YARA_DIR/yara-forge-${YARA_PACKAGE}-$(basename "$f")"
            copied=$((copied + 1))
        done <<< "$(find "$tmp/extracted" \( -name '*.yar' -o -name '*.yara' \))"

        # Restore starter rules if we stashed them.
        [ -n "$keep" ] && cp "$keep" "$YARA_DIR/starter_rules.yar"

        if [ "$copied" -gt 0 ]; then
            date +%s > "$YARA_STAMP"
            echo "=== YARA-Forge rules updated: $copied file(s) ==="
        else
            echo "=== Warning: download succeeded but no .yar files found ==="
        fi
    else
        echo "=== Could not download/extract YARA-Forge rules (offline?). Using existing set. ==="
    fi

    rm -rf "$tmp"
}

# ============================================================================
#  Kick off both updates in the background - never block startup
# ============================================================================

if sigma_should_update; then
    echo "=== Hayabusa Sigma rules will update in background ==="
    update_hayabusa &
else
    existing=$(find "$SIGMA_DIR" -name '*.yml' 2>/dev/null | wc -l | tr -d ' ')
    echo "=== Hayabusa Sigma rules fresh ($existing rules, skipping update) ==="
fi

if yara_should_update; then
    echo "=== YARA-Forge rules will update in background ==="
    update_yara_forge &
else
    existing=$(find "$YARA_DIR" -name '*.yar' 2>/dev/null | wc -l | tr -d ' ')
    echo "=== YARA-Forge rules fresh ($existing file(s), skipping update) ==="
fi

echo "=== Starting IR Platform API ==="
# Clear any stale Python bytecode cache. With the app code mounted as a
# volume, a stale .pyc (mismatched mtime) can make the container keep running
# OLD code even after the source is updated - the exact symptom where fixes
# in sigma_engine.py didn't take effect. Disabling bytecode writing + clearing
# the cache guarantees the latest source is what runs.
find /app -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
export PYTHONDONTWRITEBYTECODE=1
# --reload-dir scopes the watcher to the mounted app dir so every .py change
# (including sigma_engine.py) triggers a clean reload.
exec uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload --reload-dir /app/app
