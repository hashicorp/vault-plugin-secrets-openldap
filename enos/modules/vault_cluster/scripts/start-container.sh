#!/usr/bin/env bash
set -euo pipefail

CONTAINER_CMD="docker"

echo "Using container runtime: ${CONTAINER_CMD}"

# Read license from file path (following hashicorp/vault pattern)
LICENSE_FILE="${VAULT_LICENSE_PATH:-./support/vault.hclic}"

if [ ! -f "${LICENSE_FILE}" ]; then
    echo "Error: License file not found at ${LICENSE_FILE}"
    echo "Please ensure VAULT_LICENSE_PATH points to a valid license file"
    exit 1
fi

echo "Reading Vault Enterprise license from: ${LICENSE_FILE}"
VAULT_LICENSE=$(cat "${LICENSE_FILE}")

# Verify license content is not empty
if [ -z "${VAULT_LICENSE}" ] || [ "${VAULT_LICENSE}" = "" ]; then
    echo "Error: License file is empty: ${LICENSE_FILE}"
    echo "Please ensure the VAULT_LICENSE secret is properly configured"
    exit 1
fi

# Verify license looks valid (basic check for expected format)
if ! echo "${VAULT_LICENSE}" | grep -q "^[0-9a-f]"; then
    echo "Warning: License does not appear to be in expected format"
    echo "License should start with hexadecimal characters"
fi

echo "Successfully loaded Vault Enterprise license"

# Stop and remove existing container if it exists
if ${CONTAINER_CMD} ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "Removing existing container: ${CONTAINER_NAME}"
    ${CONTAINER_CMD} stop "${CONTAINER_NAME}" || true
    ${CONTAINER_CMD} rm "${CONTAINER_NAME}" || true
fi

# Create temporary directory for Vault config
TEMP_DIR=$(mktemp -d)
trap "rm -rf ${TEMP_DIR}" EXIT

# Write license file (using printf to avoid newline issues)
printf "%s" "${VAULT_LICENSE}" > "${TEMP_DIR}/vault.hclic"

# Write Vault configuration
cat > "${TEMP_DIR}/vault.hcl" <<EOF
storage "inmem" {}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

api_addr = "http://0.0.0.0:8200"
ui = true
EOF

# Start Vault container
echo "Starting Vault Enterprise ${VAULT_VERSION} container: ${CONTAINER_NAME}"
${CONTAINER_CMD} run -d \
    --name "${CONTAINER_NAME}" \
    --network "${NETWORK_NAME}" \
    -p "0.0.0.0:${VAULT_PORT}:8200" \
    -v "${TEMP_DIR}/vault.hcl:/vault/config/vault.hcl:ro" \
    -e VAULT_LICENSE="${VAULT_LICENSE}" \
    --cap-add=IPC_LOCK \
    "hashicorp/vault-enterprise:${VAULT_VERSION}-ent" \
    server

# Wait for Vault to be ready
echo "Waiting for Vault to be ready..."
max_attempts=30
attempt=0
while [ $attempt -lt $max_attempts ]; do
    if curl -sf "http://127.0.0.1:${VAULT_PORT}/v1/sys/health" &> /dev/null; then
        echo "Vault is responding!"
        break
    fi
    attempt=$((attempt + 1))
    echo "Waiting for Vault... (attempt $attempt/$max_attempts)"
    sleep 2
done

if [ $attempt -eq $max_attempts ]; then
    echo "Error: Vault failed to become ready"
    ${CONTAINER_CMD} logs "${CONTAINER_NAME}"
    exit 1
fi

# Initialize Vault
echo "Initializing Vault..."
INIT_OUTPUT=$(curl -sf -X PUT "http://127.0.0.1:${VAULT_PORT}/v1/sys/init" \
    -d '{"secret_shares": 1, "secret_threshold": 1}')

UNSEAL_KEY=$(echo "${INIT_OUTPUT}" | grep -o '"keys":\["[^"]*"' | cut -d'"' -f4)
ROOT_TOKEN=$(echo "${INIT_OUTPUT}" | grep -o '"root_token":"[^"]*"' | cut -d'"' -f4)

# Unseal Vault
echo "Unsealing Vault..."
curl -sf -X PUT "http://127.0.0.1:${VAULT_PORT}/v1/sys/unseal" \
    -d "{\"key\": \"${UNSEAL_KEY}\"}" > /dev/null

# Verify Vault is unsealed and ready
if curl -sf "http://127.0.0.1:${VAULT_PORT}/v1/sys/health" | grep -q '"sealed":false'; then
    echo "Vault is initialized, unsealed, and ready!"
    echo "Root token: ${ROOT_TOKEN}"
else
    echo "Error: Vault is not properly unsealed"
    ${CONTAINER_CMD} logs "${CONTAINER_NAME}"
    exit 1
fi
