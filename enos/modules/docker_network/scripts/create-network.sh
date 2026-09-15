#!/usr/bin/env bash
set -euo pipefail

CONTAINER_CMD="docker"

echo "Using container runtime: ${CONTAINER_CMD}"

# Create network if it doesn't exist
if ! ${CONTAINER_CMD} network inspect "${NETWORK_NAME}" &> /dev/null; then
    echo "Creating network: ${NETWORK_NAME}"
    ${CONTAINER_CMD} network create "${NETWORK_NAME}"
else
    echo "Network already exists: ${NETWORK_NAME}"
fi
