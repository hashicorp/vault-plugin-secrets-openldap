#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1
set -e

# Required ENV vars:
#   PLUGIN_PATH     - Mount path for plugin (e.g., 'local-secrets-ldap')
#   LDAP_URL        - LDAP server URL (e.g., ldap://127.0.0.1:389)
#   LDAP_BIND_DN    - LDAP bind DN (e.g., cn=admin,dc=example,dc=com)
#   LDAP_BIND_PASS  - LDAP bind password
#   LDAP_USER_DN    - LDAP user DN base (e.g., ou=users,dc=example,dc=com)
#   LDAP_SCHEMA     - LDAP schema type (e.g., openldap)

export VAULT_ADDR
export VAULT_TOKEN

fail() {
  echo "$1" 1>&2
  exit 1
}

[[ -z "$PLUGIN_PATH" ]] && fail "PLUGIN_PATH env variable has not been set"
[[ -z "$LDAP_URL" ]] && fail "LDAP_URL env variable has not been set"
[[ -z "$LDAP_BIND_DN" ]] && fail "LDAP_BIND_DN env variable has not been set"
[[ -z "$LDAP_BIND_PASS" ]] && fail "LDAP_BIND_PASS env variable has not been set"
[[ -z "$LDAP_USER_DN" ]] && fail "LDAP_USER_DN env variable has not been set"
[[ -z "$LDAP_SCHEMA" ]] && fail "LDAP_SCHEMA env variable has not been set"

echo "[configure] Configuring plugin at $PLUGIN_PATH"

vault write "${PLUGIN_PATH}/config" \
  url="${LDAP_URL}" \
  binddn="${LDAP_BIND_DN}" \
  bindpass="${LDAP_BIND_PASS}" \
  userdn="${LDAP_USER_DN}" \
  schema="${LDAP_SCHEMA}"

echo "[configure] Current plugin config:"
vault read "${PLUGIN_PATH}/config"