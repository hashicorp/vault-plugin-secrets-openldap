#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0
set -e

# Required ENV vars:
#   PLUGIN_NAME   - Name registered in Vault
#   PLUGIN_PATH   - Mount path for secrets engine (e.g., 'local-secrets-ldap')

export VAULT_ADDR
export VAULT_TOKEN

fail() {
  echo "$1" 1>&2
  exit 1
}

[[ -z "$PLUGIN_NAME" ]] && fail "PLUGIN_NAME env variable has not been set"
[[ -z "$PLUGIN_PATH" ]] && fail "PLUGIN_PATH env variable has not been set"

echo "[enable] Enabling plugin $PLUGIN_NAME at path $PLUGIN_PATH"

# Disable previous mount if exists
vault secrets disable "${PLUGIN_PATH}" || true

# Enable plugin at specified path
vault secrets enable -path="${PLUGIN_PATH}" "${PLUGIN_NAME}"

echo "[enable] Plugin $PLUGIN_NAME enabled at $PLUGIN_PATH."