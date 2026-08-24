#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# revert-plugin.sh — remove the candidate plugin from the Vault plugin catalog
#                    so that Vault falls back to the builtin released plugin
#
# Required environment variables (injected by the manage_plugin Terraform module):
#   VAULT_ADDR  — Vault API address (e.g. http://127.0.0.1:8200)
#   VAULT_TOKEN — Vault root token
#   PLUGIN_NAME — plugin catalog entry name
#                 (vault-plugin-secrets-openldap)
#
# Design:
#   Vault maintains a two-tier plugin registry:
#     1. External catalog  — entries registered via the API (overrides builtins)
#     2. Builtin registry  — plugins compiled directly into the Vault binary
#
#   Phase 1 of the upgrade scenario registered the candidate plugin binary in
#   the external catalog, causing Vault to prefer it over the builtin. Deleting
#   that external catalog entry removes the override and restores Vault to the
#   builtin released plugin automatically — no container restart is needed.
#
#   The next blackbox test run (Phase 2) enables a fresh ldap/ mount, at which
#   point Vault resolves the plugin from the builtin registry.
# ---------------------------------------------------------------------------

log_section() {
  echo ""
  echo "=== $1 ==="
}

# ---------------------------------------------------------------------------
# Step 1 — confirm the external catalog entry currently exists
# ---------------------------------------------------------------------------
log_section "Step 1/2 — Confirm external catalog entry exists"
http_status=$(curl -s -o /dev/null -w "%{http_code}" \
  --header "X-Vault-Token: ${VAULT_TOKEN}" \
  --request GET \
  "${VAULT_ADDR}/v1/sys/plugins/catalog/secret/${PLUGIN_NAME}")

if [ "${http_status}" != "200" ]; then
  echo "WARNING: catalog entry not found (HTTP ${http_status}); nothing to revert."
  exit 0
fi
echo "External catalog entry confirmed (HTTP ${http_status})."

# ---------------------------------------------------------------------------
# Step 2 — delete the external catalog entry to restore the builtin plugin
# ---------------------------------------------------------------------------
log_section "Step 2/2 — Remove external catalog entry (restore builtin)"
http_status=$(curl -s -o /dev/null -w "%{http_code}" \
  --header "X-Vault-Token: ${VAULT_TOKEN}" \
  --request DELETE \
  "${VAULT_ADDR}/v1/sys/plugins/catalog/secret/${PLUGIN_NAME}")

if [ "${http_status}" != "204" ]; then
  echo "ERROR: failed to remove external catalog entry (HTTP ${http_status})"
  exit 1
fi
echo "External catalog entry removed (HTTP ${http_status})."

log_section "Revert complete"
echo "Vault will now use the builtin released plugin for new ldap/ mounts."
