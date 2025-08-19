#!/usr/bin/env bash
source /opt/logging.sh
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0
set -e

# Required ENV vars:
#   PLUGIN_BINARY_SRC   - Where the plugin binary is (built artifact)
#   PLUGIN_DIR_VAULT          - Vault's plugin directory
#   PLUGIN_NAME         - Name to register in Vault

export VAULT_ADDR
export VAULT_TOKEN

fail() {
  echo "$1" 1>&2
  exit 1
}

[[ -z "$PLUGIN_BINARY_SRC" ]] && fail "PLUGIN_BINARY_SRC env variable has not been set"
[[ -z "$PLUGIN_DIR_VAULT" ]] && fail "PLUGIN_DIR_VAULT env variable has not been set"
[[ -z "$PLUGIN_NAME" ]] && fail "PLUGIN_NAME env variable has not been set"

echo "[register] Registering plugin: $PLUGIN_NAME"

# Calculate shasum
SHASUM="$(shasum -a 256 "${PLUGIN_DIR_VAULT}/${PLUGIN_NAME}" | awk '{print $1}')"
if [[ -z "$SHASUM" ]]; then
  echo "[register] error: shasum not set"
  exit 1
fi
echo "[register] Plugin SHA256: $SHASUM"

# Deregister any previous registration of this plugin
vault plugin deregister secret "${PLUGIN_NAME}" || true

# Register plugin with Vault
vault plugin register \
  -sha256="${SHASUM}" \
  secret "${PLUGIN_NAME}"

echo "[register] Plugin $PLUGIN_NAME registered successfully."