#!/usr/bin/env bash
# Definitively check whether the RUNNING backend has the discriminator guard.
# This bypasses caching by checking the actual loaded module in the live process.
echo "=== Sigma engine live diagnostic ==="
echo ""
echo "1. Does the source file on disk have the guard?"
docker compose exec -T backend grep -c "DISCRIMINATOR_FIELDS" app/sigma_engine.py 2>/dev/null \
  && echo "   (>0 means source has the fix)" || echo "   FILE MISSING"
echo ""
echo "2. Does the LOADED module (in memory) have the guard?"
docker compose exec -T backend python3 -c "
from app.sigma_engine import SigmaRule
has = hasattr(SigmaRule, 'DISCRIMINATOR_FIELDS')
print('   DISCRIMINATOR_FIELDS present in loaded class:', has)
print('   STATUS:', 'PASS' if has else 'FAIL - module is stale in memory')
" 2>/dev/null
echo ""
echo "3. Live test: Mint Sandstorm vs lsass PsList row:"
docker compose exec -T backend python3 -c "
import yaml
from app.sigma_engine import SigmaRule
r = SigmaRule(yaml.safe_load('''
title: Mint Sandstorm
logsource: {category: process_creation, product: windows}
detection:
  selection_parent_path:
    ParentImage|contains: ['manageengine']
  selection_child:
    Image|endswith: ['\\\\powershell.exe']
  condition: selection_parent_path and selection_child
'''))
row = {'SourceFile': 'C:/Windows/System32/lsass.exe', 'Name': 'lsass.exe', 'Pid': 1212, 'Ppid': 1080}
m = r.match_row(row)
print('   Match:', m, '(MUST be False)')
print('   STATUS:', 'PASS - guard works' if not m else 'FAIL - STALE module')
" 2>/dev/null
echo ""
echo "If 1=PASS but 2/3=FAIL: the file is updated but uvicorn did not reload it."
echo "FIX: docker compose restart backend    (forces Python to re-import)"
echo "If that fails: docker compose down && docker compose up -d --build"
