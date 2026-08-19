#!/usr/bin/env bash
set -euo pipefail

# Required environment variables (injected by the upgrade_plugin Terraform module):
#   VAULT_ADDR    — Vault API address
#   VAULT_TOKEN   — Vault root token
#   CONTAINER_NAME — name of the running Vault Docker container
#   PLUGIN_DIR    — host directory containing the staged candidate binary
#   PLUGIN_NAME   — plugin name in the Vault catalog (vault-plugin-secrets-openldap)
#   PLUGIN_MOUNT  — secrets engine mount path to reload (ldap)

readonly CONTAINER_CMD="docker"
readonly PLUGIN_BINARY_PATH="${PLUGIN_DIR}/${PLUGIN_NAME}"
readonly PLUGIN_DEST="/vault/plugins/${PLUGIN_NAME}"

log_section() {
  echo "=== $1 ==="
}

# ---------------------------------------------------------------------------
# Step 1 — copy the candidate binary into the running container
# ---------------------------------------------------------------------------
log_section "Copying candidate plugin into container"
echo "  host:      ${PLUGIN_BINARY_PATH}"
echo "  container: ${CONTAINER_NAME}:${PLUGIN_DEST}"

# Ensure the destination directory exists inside the container.
# Podman (used on CI runners) requires the destination directory to exist
# before `cp`; it will error with "could not be found" otherwise.
$CONTAINER_CMD exec "${CONTAINER_NAME}" mkdir -p "$(dirname "${PLUGIN_DEST}")"

$CONTAINER_CMD cp "${PLUGIN_BINARY_PATH}" "${CONTAINER_NAME}:${PLUGIN_DEST}"
$CONTAINER_CMD exec "${CONTAINER_NAME}" chmod +x "${PLUGIN_DEST}"
echo "Copy complete."

# ---------------------------------------------------------------------------
# Step 2 — compute the SHA256 of the binary inside the container
# sha256sum is available in the Vault Enterprise image via busybox
# ---------------------------------------------------------------------------
log_section "Computing plugin SHA256"
PLUGIN_SHA256=$($CONTAINER_CMD exec "${CONTAINER_NAME}" sh -c "sha256sum '${PLUGIN_DEST}' | awk '{print \$1}'")
echo "  SHA256: ${PLUGIN_SHA256}"

# ---------------------------------------------------------------------------
# Step 3 — register the new binary in the Vault plugin catalog
# This tells Vault to trust the new SHA256 for the existing plugin name.
# ---------------------------------------------------------------------------
log_section "Registering candidate plugin in Vault catalog"
curl -sf \
  --header "X-Vault-Token: ${VAULT_TOKEN}" \
  --request PUT \
  --data "{\"sha256\": \"${PLUGIN_SHA256}\", \"command\": \"${PLUGIN_NAME}\"}" \
  "${VAULT_ADDR}/v1/sys/plugins/catalog/secret/${PLUGIN_NAME}"
echo "Plugin registered."

# ---------------------------------------------------------------------------
# Step 4 — reload the secrets engine mount to hot-swap the running plugin
# Vault replaces the plugin process without restarting the server or losing
# any mount state (roles, leases, configuration).
# ---------------------------------------------------------------------------
log_section "Reloading secrets engine mount: ${PLUGIN_MOUNT}"
curl -sf \
  --header "X-Vault-Token: ${VAULT_TOKEN}" \
  --request PUT \
  --data "{\"mounts\": [\"${PLUGIN_MOUNT}/\"]}" \
  "${VAULT_ADDR}/v1/sys/plugins/reload/backend"
echo "Plugin reloaded."

log_section "Upgrade complete"
echo "Vault is now running the candidate plugin at mount: ${PLUGIN_MOUNT}/"
