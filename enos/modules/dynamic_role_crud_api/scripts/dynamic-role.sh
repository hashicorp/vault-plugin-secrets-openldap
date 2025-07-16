#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1
set -e

# Test Vault LDAP Dynamic Role CRUD and credential lifecycle using provided LDIFs.
# Assumptions:
# - You have uploaded creation.ldif, deletion.ldif, and rollback.ldif to the server.
# - Vault CLI is authenticated and VAULT_ADDR and VAULT_TOKEN are set.
# - Required ENV vars:
#     PLUGIN_PATH (e.g., local-secrets-ldap)
#     ROLE_NAME   (e.g., adam)
#     LDAP_HOST
#     LDAP_PORT
#     LDAP_USER_DN_TPL (e.g., uid={{username}},ou=users,dc=example,dc=com)
#     LDIF_PATH (path to directory containing creation.ldif, deletion.ldif, rollback.ldif)

fail() {
  echo "$1" 1>&2
  exit 1
}

[[ -z "$ROLE_NAME" ]] && fail "ROLE_NAME env variable has not been set"
[[ -z "$LDAP_HOST" ]] && fail "LDAP_HOST env variable has not been set"
[[ -z "$LDAP_PORT" ]] && fail "LDAP_PORT env variable has not been set"
[[ -z "$LDAP_USER_DN_TPL" ]] && fail "LDAP_USER_DN_TPL env variable has not been set"
[[ -z "$LDIF_PATH" ]] && fail "LDIF_PATH env variable has not been set"

export VAULT_ADDR
export VAULT_TOKEN

ROLE_PATH="${PLUGIN_PATH}/role/${ROLE_NAME}"

echo "==> Creating dynamic role: ${ROLE_NAME}"
vault write "${ROLE_PATH}" \
    creation_ldif=@${LDIF_PATH}/creation.ldif \
    deletion_ldif=@${LDIF_PATH}/deletion.ldif \
    rollback_ldif=@${LDIF_PATH}/rollback.ldif \
    default_ttl="2m" \
    max_ttl="10m"

echo "==> Reading dynamic role"
vault read "${ROLE_PATH}"

echo "==> Listing dynamic roles"
vault list "${PLUGIN_PATH}/role"

echo "==> Requesting dynamic credentials"
CRED_PATH="${PLUGIN_PATH}/creds/${ROLE_NAME}"
DYNAMIC_CREDS="$(vault read -format=json "${CRED_PATH}")"
DYN_USERNAME=$(echo "${DYNAMIC_CREDS}" | jq -r .data.username)
DYN_PASSWORD=$(echo "${DYNAMIC_CREDS}" | jq -r .data.password)
LEASE_ID=$(echo "${DYNAMIC_CREDS}" | jq -r .lease_id)

echo "==> Got dynamic username: ${DYN_USERNAME}"
echo "==> Got dynamic password: ${DYN_PASSWORD}"
echo "==> Lease ID: ${LEASE_ID}"

# Build the DN for the dynamic user
DYN_DN=${LDAP_USER_DN_TPL/\{\{username\}\}/$DYN_USERNAME}

echo "==> Verifying login with dynamic credentials"
if ldapwhoami -h "${LDAP_HOST}:${LDAP_PORT}" -x -w "${DYN_PASSWORD}" -D "${DYN_DN}"; then
  echo "[OK] Dynamic user login succeeded."
else
  echo "[ERROR] Dynamic user login failed!"
  exit 1
fi

echo "==> Revoking dynamic credentials (deletes LDAP user)"
vault lease revoke "${LEASE_ID}"

sleep 2

echo "==> Verifying dynamic user is deleted"
if ldapwhoami -h "${LDAP_HOST}:${LDAP_PORT}" -x -w "${DYN_PASSWORD}" -D "${DYN_DN}"; then
  echo "[ERROR] Dynamic user still exists after lease revoke!"
  exit 1
else
  echo "[OK] Dynamic user deleted as expected."
fi

echo "==> Deleting dynamic role"
vault delete "${ROLE_PATH}"

echo "==> Confirming dynamic role deletion"
if vault read "${ROLE_PATH}"; then
  echo "[ERROR] Dynamic role still exists after deletion!"
  exit 1
else
  echo "[OK] Dynamic role deleted successfully."
fi

echo "==> Dynamic role CRUD and credential lifecycle test: SUCCESS"