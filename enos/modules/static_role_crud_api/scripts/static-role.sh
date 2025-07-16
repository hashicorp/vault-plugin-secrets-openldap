#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1
set -e

# Test Vault LDAP Static Role CRUD and credential lifecycle using provided LDIFs.
# Assumptions:
# - Vault CLI is authenticated and VAULT_ADDR and VAULT_TOKEN are set.
# - Required ENV vars:
#     PLUGIN_PATH      - Path to the mounted plugin secrets engine (e.g., ldap-secrets/)
#     LDAP_HOST        - LDAP server hostname or IP (e.g., 127.0.0.1)
#     LDAP_PORT        - LDAP server port (e.g., 389)
#     LDAP_DN          - User DN (e.g., uid=mary.smith,ou=users,dc=example,dc=com)
#     LDAP_USERNAME    - LDAP username (e.g., mary.smith)
#     LDAP_OLD_PASSWORD - The original LDAP password for testing (before Vault rotation)
#     ROLE_NAME       - Name of the static role to create (e.g., mary)

fail() {
  echo "$1" 1>&2
  exit 1
}

[[ -z "$PLUGIN_PATH" ]] && fail "PLUGIN_PATH env variable has not been set"
[[ -z "$LDAP_HOST" ]] && fail "LDAP_HOST env variable has not been set"
[[ -z "$LDAP_PORT" ]] && fail "LDAP_PORT env variable has not been set"
[[ -z "$LDAP_DN" ]] && fail "LDAP_DN env variable has not been set"
[[ -z "$LDAP_USERNAME" ]] && fail "LDAP_USERNAME env variable has not been set"
[[ -z "$LDAP_OLD_PASSWORD" ]] && fail "LDAP_OLD_PASSWORD env variable has not been set"
[[ -z "$ROLE_NAME" ]] && fail "ROLE_NAME env variable has not been set"

export VAULT_ADDR
export VAULT_TOKEN

ROLE_PATH="${PLUGIN_PATH}/static-role/${ROLE_NAME}"
CRED_PATH="${PLUGIN_PATH}/static-cred/${ROLE_NAME}"

echo "==> LDAP_HOST: ${LDAP_HOST}"
echo "==> LDAP_PORT: ${LDAP_PORT}"

echo "==> Creating static role ${ROLE_NAME}"
vault write "${ROLE_PATH}" \
    dn="${LDAP_DN}" \
    username="${LDAP_USERNAME}" \
    rotation_period="5m"

echo "==> Reading static role"
vault read "${ROLE_PATH}"

echo "==> Reading credentials"
vault read "${CRED_PATH}"

echo "==> Listing all static roles"
vault list "${PLUGIN_PATH}/static-role"

echo "==> LDAP check: old password should fail after rotation"
if ldapwhoami -h "${LDAP_HOST}:${LDAP_PORT}" -x -w "${LDAP_OLD_PASSWORD}" -D "${LDAP_DN}"; then
  echo "[ERROR] Old password still works! Rotation failed."
  exit 1
else
  echo "[OK] Old password rejected as expected."
fi

echo "==> LDAP check: new password should succeed"
NEW_PASSWORD=$(vault read -field=password "${CRED_PATH}")
if ldapwhoami -h "${LDAP_HOST}:${LDAP_PORT}" -x -w "${NEW_PASSWORD}" -D "${LDAP_DN}"; then
  echo "[OK] New password accepted as expected."
else
  echo "[ERROR] New password did not work!"
  exit 1
fi

echo "==> Updating static role (change rotation_period)"
vault write "${ROLE_PATH}" \
    dn="${LDAP_DN}" \
    username="${LDAP_USERNAME}" \
    rotation_period="10m"

echo "==> Reading updated static role"
vault read "${ROLE_PATH}"

echo "==> Deleting static role"
vault delete "${ROLE_PATH}"

echo "==> Confirming deletion"
if vault read "${ROLE_PATH}"; then
  echo "[ERROR] Static role still exists after deletion!"
  exit 1
else
  echo "[OK] Static role deleted successfully."
fi