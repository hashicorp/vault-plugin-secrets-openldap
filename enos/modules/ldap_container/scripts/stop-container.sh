#!/usr/bin/env bash
set -euo pipefail

CONTAINER_CMD="docker"

echo "Using container runtime: ${CONTAINER_CMD}"

# Stop and remove container if it exists
if ${CONTAINER_CMD} ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "Stopping and removing container: ${CONTAINER_NAME}"
    ${CONTAINER_CMD} stop "${CONTAINER_NAME}" || true
    ${CONTAINER_CMD} rm "${CONTAINER_NAME}" || true
else
    echo "Container does not exist: ${CONTAINER_NAME}"
fi
