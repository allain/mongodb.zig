#!/usr/bin/env bash
set -euo pipefail

# Integration test runner — uses docker compose to run the test binary against
# MongoDB on an internal network (no host port binding).
#
# Usage: integration-test.sh <test-binary>

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

echo "Running integration tests via docker compose..."
docker compose -f "$COMPOSE_FILE" run --rm \
    -v "$SCRIPT_DIR:/workspace:ro" \
    test-runner "/workspace/$REL_BIN"
