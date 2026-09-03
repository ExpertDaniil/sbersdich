#!/bin/sh
set -eu

REPO_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

printf '%s\n' "[1/2] Checking C-03 fix-sqli-login"
"$REPO_DIR/security/tasks/c03_fix_sqli_login/verify.sh"

printf '%s\n' "[2/2] Checking C-04 regression package"
"$REPO_DIR/security/tasks/c04_regression_verification/verify_package.sh"

printf '%s\n' "All available security checks passed"
