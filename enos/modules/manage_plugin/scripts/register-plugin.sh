#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# register-plugin.sh — register the candidate plugin in the Vault plugin catalog
#
# Required environment variables (injected by the manage_plugin Terraform module):
#   VAULT_ADDR     — Vault API address (e.g. http://127.0.0.1:8200)
#   VAULT_TOKEN    — Vault root token
#   CONTAINER_NAME — name of the running Vault Docker container
#   PLUGIN_DIR     — host directory containing the staged candidate binary
#   PLUGIN_NAME    — plugin filename and catalog entry name
#                    (vault-plugin-secrets-openldap)
#
# Design:
#   The plugin directory is bind-mounted from the host staging directory into
#   the container at /vault/plugins/, so the candidate binary is already
#   visible inside the container as soon as stage_candidate_plugin writes it
#   to the host. There is no need to docker cp anything here.
#
#   A reload is not performed. The blackbox tests enable a fresh ldap/ mount
#   for each test run, so there is no persistent mount to reload between
#   Phase 1 and Phase 2. Vault will load the candidate binary (already on disk)
#   the next time the tests enable the mount.
# ---------------------------------------------------------------------------

readonly PLUGIN_CONTAINER_PATH="/vault/plugins/${PLUGIN_NAME}"

log_section() {
  echo ""
  echo "=== $1 ==="
}

# ---------------------------------------------------------------------------
# Step 1 — verify the candidate binary is present inside the container
# The binary was written to the host staging directory by stage_candidate_plugin
# and is visible in the container via the bind-mount.
# ---------------------------------------------------------------------------
log_section "Step 1/2 — Verify candidate binary is present in container"
docker exec "${CONTAINER_NAME}" ls -lh "${PLUGIN_CONTAINER_PATH}"

log_section "Computing candidate binary SHA256"
PLUGIN_SHA256=$(docker exec "${CONTAINER_NAME}" sh -c "sha256sum '${PLUGIN_CONTAINER_PATH}' | awk '{print \$1}'")
echo "  SHA256: ${PLUGIN_SHA256}"

# ---------------------------------------------------------------------------
# Step 2 — register the candidate binary in the Vault plugin catalog
# Updates the catalog entry's sha256 field so Vault will trust and load the
# candidate binary the next time the ldap/ mount is enabled.
# ---------------------------------------------------------------------------
log_section "Step 2/2 — Register candidate plugin in Vault catalog"
response_body=$(mktemp)
http_status=$(curl -s -o "${response_body}" -w "%{http_code}" \
  --header "X-Vault-Token: ${VAULT_TOKEN}" \
  --request PUT \
  --data "{\"sha256\": \"${PLUGIN_SHA256}\", \"command\": \"${PLUGIN_NAME}\"}" \
  "${VAULT_ADDR}/v1/sys/plugins/catalog/secret/${PLUGIN_NAME}")

if [ "${http_status}" != "204" ]; then
  echo "ERROR: plugin catalog registration failed (HTTP ${http_status})"
  echo "Response: $(cat "${response_body}")"
  rm -f "${response_body}"
  exit 1
fi
rm -f "${response_body}"
echo "Plugin registered successfully (HTTP ${http_status})."

log_section "Registration complete"
echo "Vault catalog updated with candidate plugin SHA256."
echo "Phase-1 tests will load the candidate binary from ${PLUGIN_CONTAINER_PATH}"
echo "when they next enable the ldap/ mount."
