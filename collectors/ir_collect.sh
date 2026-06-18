#!/usr/bin/env bash
#
# IR Collector — Standalone forensic artifact collector for Linux/macOS
# No dependencies beyond standard OS tools
#
# Usage:
#   chmod +x ir_collect.sh
#   sudo ./ir_collect.sh          # Full collection (recommended)
#   sudo ./ir_collect.sh --quick  # Quick triage
#

set -uo pipefail

QUICK=false
[[ "${1:-}" == "--quick" || "${1:-}" == "-q" ]] && QUICK=true

HOSTNAME=$(hostname)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
COLLECTION="IR_${HOSTNAME}_${TIMESTAMP}"
OUTDIR="/tmp/${COLLECTION}"
IS_ROOT=$([[ $EUID -eq 0 ]] && echo true || echo false)
IS_MAC=$([[ "$(uname)" == "Darwin" ]] && echo true || echo false)

mkdir -p "$OUTDIR"

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║        IR Collector (Standalone)          ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "  Host:    $HOSTNAME"
echo "  Time:    $(date '+%Y-%m-%d %H:%M:%S')"
echo "  OS:      $(uname -s) $(uname -r)"
echo "  Root:    $IS_ROOT"
echo "  Output:  $OUTDIR"
echo "  Mode:    $([ "$QUICK" = true ] && echo 'Quick triage' || echo 'Full collection')"
echo ""

if [ "$IS_ROOT" = false ]; then
    echo "  [!] Not running as root — some artifacts will be limited"
    echo ""
fi

collect() {
    local name=$1
    shift
    printf "  [*] Collecting: %s..." "$name"
    local outfile="$OUTDIR/${name}.json"
    if eval "$@" > "$outfile" 2>/dev/null; then
        local size=$(wc -c < "$outfile" | tr -d ' ')
        echo " OK (${size}B)"
    else
        echo " SKIPPED"
        echo '{"error":"not available"}' > "$outfile"
    fi
}

# Helper: convert tabular output to JSON array
to_json_array() {
    python3 -c "
import sys, json
lines = sys.stdin.read().strip().split('\n')
if len(lines) < 2:
    print('[]')
else:
    headers = lines[0].split()
    rows = []
    for line in lines[1:]:
        parts = line.split(None, len(headers)-1)
        row = {}
        for i, h in enumerate(headers):
            row[h] = parts[i] if i < len(parts) else ''
        rows.append(row)
    print(json.dumps(rows))
" 2>/dev/null || echo '[]'
}

# ═══════════════════════════════════════════
# System info
# ═══════════════════════════════════════════

collect "system_info" 'python3 -c "
import json, os, platform, datetime
print(json.dumps({
    \"hostname\": \"'$HOSTNAME'\",
    \"os\": platform.system(),
    \"os_version\": platform.version(),
    \"kernel\": platform.release(),
    \"arch\": platform.machine(),
    \"uptime\": open(\"/proc/uptime\").read().split()[0] if os.path.exists(\"/proc/uptime\") else \"unknown\",
    \"collection_time\": datetime.datetime.now().isoformat(),
    \"is_root\": '$IS_ROOT',
    \"user\": os.environ.get(\"USER\",\"unknown\")
}))"'

# ═══════════════════════════════════════════
# Processes
# ═══════════════════════════════════════════

collect "processes" 'python3 -c "
import subprocess, json, hashlib, os
result = subprocess.run([\"ps\", \"auxww\"], capture_output=True, text=True)
lines = result.stdout.strip().split(\"\n\")
procs = []
for line in lines[1:]:
    parts = line.split(None, 10)
    if len(parts) >= 11:
        exe = parts[10].split()[0] if parts[10] else \"\"
        h = \"\"
        if exe.startswith(\"/\") and os.path.isfile(exe):
            try:
                h = hashlib.sha256(open(exe,\"rb\").read()).hexdigest()
            except: pass
        procs.append({
            \"user\": parts[0], \"pid\": parts[1], \"cpu\": parts[2],
            \"mem\": parts[3], \"vsz\": parts[4], \"rss\": parts[5],
            \"stat\": parts[7], \"start\": parts[8], \"time\": parts[9],
            \"command\": parts[10], \"sha256\": h
        })
print(json.dumps(procs))"'

# ═══════════════════════════════════════════
# Network
# ═══════════════════════════════════════════

if [ "$IS_MAC" = true ]; then
    collect "network_connections" 'netstat -an -p tcp 2>/dev/null | python3 -c "
import sys, json, re
conns = []
for line in sys.stdin:
    if \"ESTABLISHED\" in line or \"LISTEN\" in line or \"SYN\" in line:
        parts = line.split()
        if len(parts) >= 5:
            conns.append({\"proto\": parts[0], \"local\": parts[3], \"remote\": parts[4], \"state\": parts[5] if len(parts) > 5 else \"\"})
print(json.dumps(conns))"'
else
    collect "network_connections" 'ss -tupn 2>/dev/null | python3 -c "
import sys, json
conns = []
for line in sys.stdin:
    parts = line.split()
    if len(parts) >= 5 and parts[0] != \"Netid\":
        conns.append({\"proto\": parts[0], \"state\": parts[1], \"local\": parts[4], \"remote\": parts[5] if len(parts) > 5 else \"\", \"process\": parts[-1] if \"pid=\" in line else \"\"})
print(json.dumps(conns))"'
fi

collect "listening_ports" 'python3 -c "
import subprocess, json
r = subprocess.run([\"ss\", \"-tlnp\"] if not '$IS_MAC' else [\"lsof\", \"-iTCP\", \"-sTCP:LISTEN\", \"-n\", \"-P\"], capture_output=True, text=True)
print(json.dumps([{\"line\": l.strip()} for l in r.stdout.strip().split(chr(10)) if l.strip()]))"'

collect "dns_resolv" 'python3 -c "
import json
try:
    data = open(\"/etc/resolv.conf\").read()
    print(json.dumps({\"resolv_conf\": data}))
except: print(\"{}\")"'

collect "arp_table" 'arp -a 2>/dev/null | python3 -c "
import sys, json
entries = []
for line in sys.stdin:
    parts = line.strip().split()
    if len(parts) >= 3:
        entries.append({\"entry\": line.strip()})
print(json.dumps(entries))"'

collect "network_interfaces" 'python3 -c "
import subprocess, json
r = subprocess.run([\"ifconfig\"] if '$IS_MAC' else [\"ip\", \"addr\"], capture_output=True, text=True)
print(json.dumps({\"output\": r.stdout}))"'

# ═══════════════════════════════════════════
# Persistence
# ═══════════════════════════════════════════

collect "crontabs" 'python3 -c "
import subprocess, json, os, glob
crons = []
# User crontabs
r = subprocess.run([\"crontab\", \"-l\"], capture_output=True, text=True)
if r.returncode == 0:
    crons.append({\"user\": os.environ.get(\"USER\",\"\"), \"type\": \"user_crontab\", \"content\": r.stdout})
# System crontabs
for d in [\"/etc/crontab\", \"/etc/cron.d\", \"/var/spool/cron\"]:
    if os.path.isfile(d):
        try: crons.append({\"path\": d, \"type\": \"system\", \"content\": open(d).read()})
        except: pass
    elif os.path.isdir(d):
        for f in glob.glob(d + \"/*\"):
            try: crons.append({\"path\": f, \"type\": \"system\", \"content\": open(f).read()})
            except: pass
print(json.dumps(crons))"'

collect "services" 'python3 -c "
import subprocess, json
services = []
r = subprocess.run([\"systemctl\", \"list-units\", \"--type=service\", \"--all\", \"--no-pager\"], capture_output=True, text=True)
if r.returncode == 0:
    for line in r.stdout.strip().split(chr(10)):
        parts = line.split(None, 4)
        if len(parts) >= 4 and \".service\" in line:
            services.append({\"unit\": parts[0].strip(\"●\").strip(), \"load\": parts[1], \"active\": parts[2], \"sub\": parts[3], \"description\": parts[4] if len(parts) > 4 else \"\"})
else:
    # macOS fallback
    r2 = subprocess.run([\"launchctl\", \"list\"], capture_output=True, text=True)
    for line in r2.stdout.strip().split(chr(10))[1:]:
        parts = line.split(None, 2)
        if len(parts) >= 3:
            services.append({\"pid\": parts[0], \"status\": parts[1], \"label\": parts[2]})
print(json.dumps(services))"'

# ═══════════════════════════════════════════
# Users & Auth
# ═══════════════════════════════════════════

collect "users" 'python3 -c "
import json
users = []
for line in open(\"/etc/passwd\"):
    parts = line.strip().split(\":\")
    if len(parts) >= 7:
        users.append({\"name\": parts[0], \"uid\": parts[2], \"gid\": parts[3], \"home\": parts[5], \"shell\": parts[6]})
print(json.dumps(users))"'

collect "ssh_authorized_keys" 'python3 -c "
import json, glob, os
keys = []
for f in glob.glob(\"/home/*/.ssh/authorized_keys\") + glob.glob(\"/root/.ssh/authorized_keys\"):
    try:
        content = open(f).read()
        keys.append({\"path\": f, \"keys\": content.strip().split(chr(10))})
    except: pass
print(json.dumps(keys))"'

collect "last_logins" 'last -50 2>/dev/null | python3 -c "
import sys, json
print(json.dumps([{\"line\": l.strip()} for l in sys.stdin if l.strip() and not l.startswith(\"wtmp\")]))"'

collect "failed_logins" 'lastb -20 2>/dev/null | python3 -c "
import sys, json
print(json.dumps([{\"line\": l.strip()} for l in sys.stdin if l.strip() and not l.startswith(\"btmp\")]))"'

# ═══════════════════════════════════════════
# Logs (auth, syslog)
# ═══════════════════════════════════════════

if [ "$QUICK" = false ]; then
    collect "auth_log" 'python3 -c "
import json, os
logfiles = [\"/var/log/auth.log\", \"/var/log/secure\"]
for f in logfiles:
    if os.path.isfile(f):
        lines = open(f).readlines()[-2000:]
        print(json.dumps([{\"line\": l.strip()} for l in lines if l.strip()]))
        break
else:
    print(\"[]\")"'

    collect "syslog_recent" 'python3 -c "
import json, os
for f in [\"/var/log/syslog\", \"/var/log/messages\"]:
    if os.path.isfile(f):
        lines = open(f).readlines()[-1000:]
        print(json.dumps([{\"line\": l.strip()} for l in lines if l.strip()]))
        break
else:
    print(\"[]\")"'

    collect "bash_history" 'python3 -c "
import json, glob, os
histories = []
for f in glob.glob(\"/home/*/.bash_history\") + glob.glob(\"/root/.bash_history\") + glob.glob(\"/home/*/.zsh_history\"):
    try:
        lines = open(f, errors=\"replace\").readlines()[-200:]
        histories.append({\"path\": f, \"lines\": [l.strip() for l in lines if l.strip()]})
    except: pass
print(json.dumps(histories))"'

    collect "recently_modified" 'find /tmp /var/tmp /dev/shm /home 2>/dev/null -type f -mtime -3 -ls 2>/dev/null | head -200 | python3 -c "
import sys, json
print(json.dumps([{\"entry\": l.strip()} for l in sys.stdin if l.strip()]))"'
fi

# ═══════════════════════════════════════════
# Installed packages
# ═══════════════════════════════════════════

collect "installed_packages" 'python3 -c "
import subprocess, json
pkgs = []
# Try dpkg
r = subprocess.run([\"dpkg\", \"-l\"], capture_output=True, text=True)
if r.returncode == 0:
    for line in r.stdout.split(chr(10)):
        if line.startswith(\"ii\"):
            parts = line.split(None, 4)
            if len(parts) >= 3:
                pkgs.append({\"name\": parts[1], \"version\": parts[2]})
else:
    # Try rpm
    r = subprocess.run([\"rpm\", \"-qa\", \"--queryformat\", \"%{NAME} %{VERSION}\n\"], capture_output=True, text=True)
    if r.returncode == 0:
        for line in r.stdout.strip().split(chr(10)):
            parts = line.split(None, 1)
            if len(parts) >= 2:
                pkgs.append({\"name\": parts[0], \"version\": parts[1]})
    else:
        # macOS
        r = subprocess.run([\"brew\", \"list\", \"--versions\"], capture_output=True, text=True)
        for line in r.stdout.strip().split(chr(10)):
            parts = line.split(None, 1)
            if parts:
                pkgs.append({\"name\": parts[0], \"version\": parts[1] if len(parts) > 1 else \"\"})
print(json.dumps(pkgs))"'

# ═══════════════════════════════════════════
# Compress
# ═══════════════════════════════════════════

echo ""
echo "  [*] Collection complete"

FILE_COUNT=$(find "$OUTDIR" -name "*.json" | wc -l | tr -d ' ')
TOTAL_SIZE=$(du -sh "$OUTDIR" 2>/dev/null | awk '{print $1}')
echo "  [*] Files: $FILE_COUNT artifacts, ${TOTAL_SIZE}"

ZIPFILE="/tmp/${COLLECTION}.zip"
echo -n "  [*] Compressing..."
if command -v zip &>/dev/null; then
    cd /tmp && zip -qr "$ZIPFILE" "$COLLECTION"
    rm -rf "$OUTDIR"
    echo " OK"
elif command -v tar &>/dev/null; then
    ZIPFILE="/tmp/${COLLECTION}.tar.gz"
    cd /tmp && tar -czf "$ZIPFILE" "$COLLECTION"
    rm -rf "$OUTDIR"
    echo " OK (tar.gz)"
else
    echo " no zip/tar available, keeping folder"
    ZIPFILE="$OUTDIR"
fi

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║  Collection complete!                     ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""
echo "  Output: $ZIPFILE"
echo ""
echo "  Upload this file to the IR Platform dashboard"
echo "  (Collector tab → Upload Collector Results)"
echo ""
