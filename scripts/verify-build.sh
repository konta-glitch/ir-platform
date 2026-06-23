#!/usr/bin/env bash
# Verify the RUNNING backend container has the false-positive fixes.
# Run this after `docker compose up -d --build` to confirm the deployed
# code matches the latest source (not a stale image).

set -e
echo "=== IR Platform build verification ==="
echo ""

# 1. Check the engine version stamped in the running container
echo "1. Engine version in running container:"
docker compose exec -T backend python3 -c \
  "from app.detection_engine import ENGINE_VERSION; print('   ' + ENGINE_VERSION)" \
  2>/dev/null || echo "   ERROR: backend not running or old image (no ENGINE_VERSION)"
echo ""

# 2. Prove the Sigma discriminator guard is active (Mint Sandstorm vs lsass)
echo "2. Sigma discriminator guard (Mint Sandstorm must NOT match lsass PsList row):"
docker compose exec -T backend python3 -c "
import yaml
from app.sigma_engine import SigmaRule
rule = SigmaRule(yaml.safe_load('''
title: Mint Sandstorm
logsource: {category: process_creation, product: windows}
detection:
  selection:
    ParentImage|endswith: \\\\java.exe
    Image|endswith: \\\\lsass.exe
  condition: selection
level: high
'''))
row = {'SourceFile': 'C:/Windows/System32/lsass.exe', 'Name': 'lsass.exe', 'Pid': 1212, 'Ppid': 1080}
result = rule.match_row(row)
print('   Match result:', result, '(MUST be False)')
print('   STATUS:', 'PASS - fix active' if result == False else 'FAIL - STALE IMAGE, rebuild needed')
" 2>/dev/null || echo "   ERROR: could not run check"
echo ""

# 3. Prove correlation rejects normal user chains
echo "3. Correlation guard (explorer->powershell must NOT be flagged):"
docker compose exec -T backend python3 -c "
from app.correlation_engine import CorrelationEngine
data = {'PsList_From_Pslist': [
    {'Name': 'explorer.exe', 'Pid': '2000', 'Ppid': '1'},
    {'Name': 'powershell.exe', 'Pid': '2300', 'Ppid': '2000'},
]}
r = CorrelationEngine().correlate(data, [])
n = len(r['suspicious_chains'])
print('   Suspicious chains:', n, '(MUST be 0)')
print('   STATUS:', 'PASS - fix active' if n == 0 else 'FAIL - STALE IMAGE, rebuild needed')
" 2>/dev/null || echo "   ERROR: could not run check"
echo ""

# 4. Run the ACTUAL deployed Sigma rules against the exact lsass/svchost rows
#    that produced the false positives. This loads the real rule files from
#    /app/sigma_rules and tests them — the definitive check.
echo "4. Real deployed Sigma rules vs lsass/svchost PsList rows:"
docker compose exec -T backend python3 -c "
from app.sigma_engine import SigmaEngine
eng = SigmaEngine(rules_dir='/app/sigma_rules')
eng.load_rules()
# The exact rows from the reports
rows = {
    'PsList_From_Pslist': [
        {'SourceFile': 'C:/Windows/System32/lsass.exe', 'Name': 'lsass.exe', 'Pid': 1212, 'Ppid': 1080, 'Threads': 9},
        {'SourceFile': 'C:/Windows/System32/svchost.exe', 'Name': 'svchost.exe', 'Pid': 3180, 'Ppid': 1168, 'Threads': 5},
    ]
}
findings = eng.analyze(rows)
bad = [f for f in findings if any(x in f['title'] for x in ['Ryuk','Mint Sandstorm','Qakbot'])]
print('   Rules loaded:', len(eng.rules))
print('   Ryuk/Mint/Qakbot matches on PsList:', len(bad), '(MUST be 0)')
for f in bad[:5]:
    print('     STILL MATCHING:', f['title'])
print('   STATUS:', 'PASS - FP fix active' if len(bad) == 0 else 'FAIL - sigma_engine.py is STALE in container')
" 2>/dev/null || echo "   ERROR: could not run check"
echo ""
echo "If check 4 shows FAIL: the container is running an OLD sigma_engine.py."
echo "Force a clean restart:  docker compose down && docker compose up -d --build"
echo "Code is volume-mounted + uvicorn --reload, but a clean restart guarantees reload."
