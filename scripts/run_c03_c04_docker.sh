#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "$#" -ne 1 ]]; then
    printf 'Usage: %s /absolute/path/to/UniversalAgenticCompetitionPublic\n' "$0" >&2
    exit 2
fi

REPO_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
PUBLIC_REPO="$(CDPATH= cd -- "$1" && pwd)"
PATCH_FILE="$REPO_DIR/security/tasks/c03_fix_sqli_login/fix_sqli_login.patch"
C04_DIR="$REPO_DIR/security/tasks/c04_regression_verification"
RESULTS_DIR="$REPO_DIR/evaluation/results/c04_manual"
IMAGE_TAG="sbersdich/c03-c04:local"
TEMP_ROOT="$(mktemp -d)"

cleanup() {
    if [[ -n "${TEMP_ROOT:-}" && -d "$TEMP_ROOT" && "$TEMP_ROOT" == /tmp/* ]]; then
        rm -rf -- "$TEMP_ROOT"
    fi
}

trap cleanup EXIT INT TERM

command -v git >/dev/null
command -v patch >/dev/null
command -v tar >/dev/null
command -v docker >/dev/null

git -C "$PUBLIC_REPO" rev-parse --is-inside-work-tree >/dev/null
mkdir -p "$RESULTS_DIR"

printf '%s\n' "Exporting the public repository commit to a temporary directory"
git -C "$PUBLIC_REPO" archive HEAD | tar -x -C "$TEMP_ROOT"

printf '%s\n' "Applying C-03 only to the temporary copy"
patch --batch --forward -d "$TEMP_ROOT" -p1 -i "$PATCH_FILE"

printf '%s\n' "Building disposable C-03 verification image"
docker build \
    --tag "$IMAGE_TAG" \
    "$TEMP_ROOT/local_task/fix-sqli-login/environment"

printf '%s\n' "Running C-04 against a fresh PostgreSQL and Uvicorn process"
docker run --rm \
    --entrypoint bash \
    --env C04_OUTPUT_DIR=/results \
    --env C04_RESET_DB=1 \
    --volume "$C04_DIR:/opt/c04:ro" \
    --volume "$RESULTS_DIR:/results" \
    "$IMAGE_TAG" \
    -lc '/opt/c04/run_in_acp.sh /app'

printf 'C-03/C-04 Docker verification passed. Results: %s\n' "$RESULTS_DIR"
