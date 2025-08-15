#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail

fail() {
  echo "$1" 1>&2
  exit 1
}

PLUGIN_PATH=local-secrets-ldap

# Required env vars: PLUGIN_PATH
if [[ -z "${PLUGIN_PATH:-}" ]]; then
  fail "PLUGIN_PATH env variable has not been set"
fi

# Configure plugin for manual rotation
vault write -format=json "${PLUGIN_PATH}/config" \
  disable_automated_rotation=true \
  rotation_period=0 \
  rotation_schedule="" \
  rotation_window=0 >/dev/null

# Read disable_automated_rotation from config
disable_automated_rotation=$(vault read -format=json "${PLUGIN_PATH}/config" | jq -r '.data.disable_automated_rotation')

# Validate disable_automated_rotation
if [[ "$disable_automated_rotation" != "true" ]]; then
  fail "[ERROR] Expected rotation_schedule=true, got $disable_automated_rotation"
fi

# Read pre-rotation timestamp
before=$(vault read -format=json "${PLUGIN_PATH}/config" | jq -r '.data.last_bind_password_rotation')

# Trigger manual rotation
vault write -format=json -f "${PLUGIN_PATH}/rotate-root" >/dev/null

# Read post-rotation timestamp after a brief pause
after=$(vault read -format=json "${PLUGIN_PATH}/config" | jq -r '.data.last_bind_password_rotation')

if [[ "$after" == "$before" ]]; then
  fail "[ERROR] Manual rotation failed: timestamp did not change (before=$before, after=$after)"
fi

echo "[OK] Manual rotation succeeded: timestamp updated (before=$before, after=$after)"
