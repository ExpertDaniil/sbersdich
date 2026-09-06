#!/bin/sh
set -eu

REPO_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

printf '%s\n' "[1/4] Checking C-03 fix-sqli-login"
"$REPO_DIR/security/tasks/c03_fix_sqli_login/verify.sh"

printf '%s\n' "[2/4] Checking C-04 regression package"
"$REPO_DIR/security/tasks/c04_regression_verification/verify_package.sh"

printf '%s\n' "[3/4] Checking C-05 incident forensics"
"$REPO_DIR/security/tasks/c05_incident_forensics/verify.sh"

printf '%s\n' "[4/4] Checking C-06/C-11 agent components"
"$REPO_DIR/agent/verify.sh"

printf '%s\n' "All available security checks passed"
