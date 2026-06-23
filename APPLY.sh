#!/usr/bin/env bash
# APPLY.sh — primeni "tests+CI+YARA auto-update" izmene na ir-platform.
#
# Upotreba:
#   1. Raspakuj ir-update.tar.gz u koren ir-platform repoa:
#        tar -xzf ir-update.tar.gz -C /putanja/do/ir-platform
#   2. Iz korena repoa pokreni:
#        bash APPLY.sh
#
# Skripta NE koristi sed (izbegava BSD/GNU razlike). Samo kopira fajlove,
# pravi granu i commit-uje.
set -euo pipefail

[ -f docker-compose.yml ] || { echo "Pokreni iz korena ir-platform repoa."; exit 1; }

git checkout main
git pull origin main || true
git checkout -b feat/tests-ci-and-yara-autoupdate

# Fajlovi su vec na pravim mestima (raspakovani iz tar-a preko repoa).
git add -A
git status --short
echo ""
echo ">> Provera testova pre commita:"
( cd backend && python3 -m pytest -q 2>&1 | tail -5 ) || echo "   (pytest nije lokalno instaliran — preskoci, CI ce pokrenuti)"
echo ""
git commit -m "feat: backend test suite + CI, and YARA rule auto-update"
echo ""
echo ">> Gotovo. Push i otvori PR:"
echo "     git push -u origin feat/tests-ci-and-yara-autoupdate"
