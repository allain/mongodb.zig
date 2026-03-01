#!/usr/bin/env bash
set -euo pipefail

# Coverage runner — uses docker compose to run kcov + test binary against
# MongoDB on an internal network. Uses the kcov/kcov Docker image.
#
# Usage: coverage.sh <test-binary>

if [ $# -lt 1 ]; then
    echo "Usage: $0 <test-binary>" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.test.yml"
REL_BIN="$(realpath --relative-to="$SCRIPT_DIR" "$1")"

cleanup() {
    echo "Tearing down containers..."
    docker compose -f "$COMPOSE_FILE" down --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

COV_DIR="coverage/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$SCRIPT_DIR/$COV_DIR"

echo "Running coverage via docker compose..."
docker compose -f "$COMPOSE_FILE" run --rm \
    --user "$(id -u):$(id -g)" \
    -v "$SCRIPT_DIR:/workspace" \
    coverage-runner \
    kcov --replace-src-path="$SCRIPT_DIR:/workspace" --include-path=/workspace/src "/workspace/$COV_DIR" "/workspace/$REL_BIN"

echo "Coverage report: $COV_DIR/index.html"
