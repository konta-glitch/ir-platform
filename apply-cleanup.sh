#!/usr/bin/env bash
# apply-cleanup.sh — primeni sredjivanje strukture na ir-platform
# Pokreni iz KORENA repoa (gde je docker-compose.yml).
set -euo pipefail

[ -f docker-compose.yml ] || { echo "Pokreni iz korena ir-platform repoa."; exit 1; }

git checkout -b chore/repo-cleanup

# 1. Izbaci veliki YARA-Forge ruleset iz git-a (ostaje na disku)
git rm --cached backend/yara_rules/yara-forge-core-yara-rules-core.yar

# 2. Obrisi zastareli duplikat
git rm -r detection-package

# 3. Reorganizuj root
mkdir -p scripts docs
git mv diagnose.sh diagnose-sigma.sh setup.sh ir.sh verify-build.sh \
       install-yara-rules.sh install-sigma-rules.sh scripts/
git mv SETUP-GUIDE.md VALIDATION-PLAYBOOK.md docs/

# 4. Popravi putanje u install skriptama (SCRIPT_DIR -> REPO_ROOT)
sed -i 's#RULES_DIR="$SCRIPT_DIR/backend/yara_rules"#REPO_ROOT="$(cd "$SCRIPT_DIR/.." \&\& pwd)"\nRULES_DIR="$REPO_ROOT/backend/yara_rules"#' scripts/install-yara-rules.sh
sed -i 's#RULES_DIR="$SCRIPT_DIR/sigma_rules"#REPO_ROOT="$(cd "$SCRIPT_DIR/.." \&\& pwd)"\nRULES_DIR="$REPO_ROOT/sigma_rules"#' scripts/install-sigma-rules.sh
sed -i 's#\./install-sigma-rules.sh#./scripts/install-sigma-rules.sh#g' sigma_rules/README.md

# 5. .gitignore — ignorisi preuzeta pravila
python3 - <<'PY'
s=open(".gitignore").read()
s=s.replace("""sigma_rules/hayabusa/
sigma_rules/.hayabusa_last_update""","""sigma_rules/hayabusa/
sigma_rules/sigmahq/
sigma_rules/.hayabusa_last_update

# Downloaded detection rules (fetched via scripts/, never committed)
backend/yara_rules/*
!backend/yara_rules/starter_rules.yar""")
open(".gitignore","w").write(s)
PY

# 6. README.md i CONTRIBUTING.md -> kopiraj prilozene fajlove preko ovih, pa:
echo ">> Sada kopiraj prilozene README.md i CONTRIBUTING.md u koren repoa."
echo ">> Zatim: git add -A && git commit"
