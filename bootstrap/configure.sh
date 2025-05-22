# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

set -x
PLUGIN_DIR=$1
PLUGIN_NAME=$2
PLUGIN_PATH=$3

echo "==> PLUGIN_DIR: $PLUGIN_DIR"
echo "==> PLUGIN_NAME: $PLUGIN_NAME"
echo "==> PLUGIN_PATH: $PLUGIN_PATH"

# Try to clean-up previous runs
vault secrets disable "${PLUGIN_PATH}"
vault plugin deregister secret "${PLUGIN_NAME}"
killall "${PLUGIN_NAME}"

# Copy the binary so text file is not busy when rebuilding & the plugin is registered
cp ./bin/"$PLUGIN_NAME" "$PLUGIN_DIR"

SHASUM="$(shasum -a 256 "$PLUGIN_DIR"/"$PLUGIN_NAME" | awk '{print $1}')"
if [[ -z "$SHASUM" ]]; then echo "error: shasum not set"; exit 1; fi

# Sets up the binary with local changes
vault plugin register \
    -sha256="${SHASUM}" \
    secret "${PLUGIN_NAME}"

vault secrets enable -path="${PLUGIN_PATH}" "${PLUGIN_NAME}"

vault write ${PLUGIN_PATH}/config \
    url="ldap://127.0.0.1:389" \
    binddn="cn=admin,dc=example,dc=com" \
    bindpass="adminpassword" \
    userdn="ou=users,dc=example,dc=com" \
    schema="openldap"

vault read ${PLUGIN_PATH}/config

# mary.smith must be removed from all library sets
# before being managed by this static role.
vault write ${PLUGIN_PATH}/static-role/mary \
    dn="uid=mary.smith,ou=users,dc=example,dc=com" \
    username="mary.smith" \
    rotation_period="10s"

vault read ${PLUGIN_PATH}/static-role/mary
# Read the current password for mary
vault read ${PLUGIN_PATH}/static-cred/mary

# should fail with original password after import rotation
ldapwhoami -h 127.0.0.1:389 -x -w "defaultpassword" -D "uid=mary.smith,ou=users,dc=example,dc=com"

# should succeed with new password
ldapwhoami -h 127.0.0.1:389 -x -w "$(vault read -field password ${PLUGIN_PATH}/static-cred/mary)" -D "uid=mary.smith,ou=users,dc=example,dc=com"
