#!/usr/bin/env bash
set -euo pipefail

# Integration test runner — manages a Docker MongoDB container and runs the
# test binary with MONGO_URI set.
#
# Usage: integration-test.sh <test-binary>

if [ $# -lt 1 ]; then
    echo "Usage: $0 <test-binary>" >&2
    exit 1
fi

TEST_BIN="$1"
CONTAINER_NAME="zig-mongo-test-$$"
MONGO_PORT=27099

cleanup() {
    echo "Stopping MongoDB container..."
    docker stop "$CONTAINER_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

MONGO_USER="testuser"
MONGO_PASS="testpass"

echo "Starting MongoDB container ($CONTAINER_NAME) on port $MONGO_PORT with auth..."
docker run --rm -d \
    --name "$CONTAINER_NAME" \
    -p "$MONGO_PORT:27017" \
    -e MONGO_INITDB_ROOT_USERNAME="$MONGO_USER" \
    -e MONGO_INITDB_ROOT_PASSWORD="$MONGO_PASS" \
    mongo:7 >/dev/null

# Wait for MongoDB to be ready (up to 30 seconds)
echo "Waiting for MongoDB to be ready..."
for i in $(seq 1 30); do
    if docker exec "$CONTAINER_NAME" mongosh --quiet -u "$MONGO_USER" -p "$MONGO_PASS" --eval "db.runCommand({ping:1})" >/dev/null 2>&1; then
        echo "MongoDB ready after ${i}s"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "Error: MongoDB did not become ready in 30s" >&2
        exit 1
    fi
    sleep 1
done

export MONGO_URI="mongodb://$MONGO_USER:$MONGO_PASS@localhost:$MONGO_PORT/zig_mongo_test?authSource=admin"
echo "Running tests with MONGO_URI=$MONGO_URI"
"$TEST_BIN"
