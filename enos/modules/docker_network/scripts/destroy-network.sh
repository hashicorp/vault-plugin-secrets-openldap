#!/usr/bin/env bash
set -euo pipefail

CONTAINER_CMD="docker"

echo "Using container runtime: ${CONTAINER_CMD}"

# Remove network if it exists
if ${CONTAINER_CMD} network inspect "${NETWORK_NAME}" &> /dev/null; then
    echo "Removing network: ${NETWORK_NAME}"
    ${CONTAINER_CMD} network rm "${NETWORK_NAME}" || true
else
    echo "Network does not exist: ${NETWORK_NAME}"
fi
