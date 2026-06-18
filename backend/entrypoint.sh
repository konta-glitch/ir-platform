#!/usr/bin/env bash
#
# entrypoint.sh — runs on container start (every rebuild/restart).
# Auto-updates Hayabusa Sigma rules, then launches the API.
#
# The update is best-effort: if GitHub is unreachable or rules already
# exist and are fresh, it skips gracefully so startup is never blocked.
#

set -uo pipefail

RULES_DIR="/app/sigma_rules"
HAYABUSA_DIR="$RULES_DIR/hayabusa"
STAMP_FILE="$RULES_DIR/.hayabusa_last_update"
# Re-fetch at most once every 24h (86400s) unless forced
MAX_AGE=${SIGMA_UPDATE_INTERVAL:-86400}
FORCE_UPDATE=${SIGMA_FORCE_UPDATE:-false}

mkdir -p "$RULES_DIR"

should_update() {
    [ "$FORCE_UPDATE" = "true" ] && return 0
    # Update if rules missing
    [ ! -d "$HAYABUSA_DIR" ] && return 0
    [ -z "$(find "$HAYABUSA_DIR" -name '*.yml' 2>/dev/null | head -1)" ] && return 0
    # Update if stamp is old
    if [ -f "$STAMP_FILE" ]; then
        local last now age
        last=$(cat "$STAMP_FILE" 2>/dev/null || echo 0)
        now=$(date +%s)
        age=$((now - last))
        [ "$age" -gt "$MAX_AGE" ] && return 0
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
            date +%s > "$STAMP_FILE"
            echo "=== Hayabusa rules updated: $copied rules ==="
        else
            echo "=== Warning: clone succeeded but no rules copied ==="
        fi
    else
        echo "=== Could not update Hayabusa rules (offline?). Using existing set. ==="
    fi

    rm -rf "$tmp"
}

# Always start the API. Rule updates happen in the background and never
# block startup — even on first boot we ship with builtin_rules.yml so the
# platform is functional immediately.
if should_update; then
    echo "=== Hayabusa rules will update in background ==="
    update_hayabusa &
else
    existing=$(find "$RULES_DIR" -name '*.yml' 2>/dev/null | wc -l | tr -d ' ')
    echo "=== Hayabusa rules fresh ($existing rules, skipping update) ==="
fi

echo "=== Starting IR Platform API ==="
# Clear any stale Python bytecode cache. With the app code mounted as a
# volume, a stale .pyc (mismatched mtime) can make the container keep running
# OLD code even after the source is updated — the exact symptom where fixes
# in sigma_engine.py didn't take effect. Disabling bytecode writing + clearing
# the cache guarantees the latest source is what runs.
find /app -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
export PYTHONDONTWRITEBYTECODE=1
# --reload-dir scopes the watcher to the mounted app dir so every .py change
# (including sigma_engine.py) triggers a clean reload.
exec uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload --reload-dir /app/app
