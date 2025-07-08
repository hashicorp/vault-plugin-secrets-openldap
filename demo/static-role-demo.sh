#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

set -e

# Required ENV vars:
#   PLUGIN_PATH      - Path to the mounted plugin secrets engine (e.g., ldap-secrets/)
#   LDAP_HOST        - LDAP server hostname or IP (e.g., 127.0.0.1)
#   LDAP_PORT        - LDAP server port (e.g., 389)
#   LDAP_DN          - User DN (e.g., uid=mary.smith,ou=users,dc=example,dc=com)
#   LDAP_USERNAME    - LDAP username (e.g., mary.smith)
#   LDAP_OLD_PASSWORD - The original LDAP password for testing (before Vault rotation)
LDAP_HOST=10.13.2.56 # placeholder for your LDAP server (get from ec2 instance where LDAP is running using 'hostname -I')
LDAP_PORT=389
LDAP_DN=uid=mary.smith,ou=users,dc=example,dc=com
LDAP_USERNAME=mary.smith
LDAP_OLD_PASSWORD=defaultpassword
PLUGIN_PATH=${PLUGIN_PATH:-local-secrets-ldap}

ROLE_NAME="mary"
ROLE_PATH="${PLUGIN_PATH}/static-role/${ROLE_NAME}"
CRED_PATH="${PLUGIN_PATH}/static-cred/${ROLE_NAME}"

pause() {
  echo ""
  echo "Press [ENTER] to continue..."
  read
  echo ""
}

announce() {
  echo ""
  echo "##########################################################"
  echo "# $1"
  echo "##########################################################"
  echo ""
}

announce "Demo: LDAP Static Credentials Rotation via Vault"
echo "This demo will walk through the lifecycle of a Vault LDAP static credential."
pause

announce "Step 1: Creating static role '${ROLE_NAME}'"
echo "We will create a static role in Vault for LDAP user '${LDAP_USERNAME}'."
echo "Command:"
echo "vault write \"${ROLE_PATH}\" \\"
echo "    dn=\"${LDAP_DN}\" \\"
echo "    username=\"${LDAP_USERNAME}\" \\"
echo "    rotation_period=\"5m\""
pause
vault write "${ROLE_PATH}" \
    dn="${LDAP_DN}" \
    username="${LDAP_USERNAME}" \
    rotation_period="5m"

announce "Step 2: Reading static role info"
echo "Let's inspect the static role configuration in Vault."
echo "Command: vault read \"${ROLE_PATH}\""
pause
vault read "${ROLE_PATH}"

announce "Step 3: Fetching the LDAP credentials from Vault"
echo "This retrieves the generated LDAP credentials from Vault."
echo "Command: vault read \"${CRED_PATH}\""
pause
vault read "${CRED_PATH}"

announce "Step 4: Listing all static roles"
echo "See all static roles in the configured Vault path."
echo "Command: vault list \"${PLUGIN_PATH}/static-role\""
pause
vault list "${PLUGIN_PATH}/static-role"

announce "Step 5: LDAP check -- old password should fail after rotation"
echo "We'll verify that the old LDAP password no longer works."
echo "Command: ldapwhoami -h \"${LDAP_HOST}:${LDAP_PORT}\" -x -w \"<OLD_PASSWORD>\" -D \"${LDAP_DN}\""
pause
if ldapwhoami -h "${LDAP_HOST}:${LDAP_PORT}" -x -w "${LDAP_OLD_PASSWORD}" -D "${LDAP_DN}"; then
  echo "[ERROR] Old password still works! Rotation failed."
  exit 1
else
  echo "[OK] Old password rejected as expected."
fi

announce "Step 6: LDAP check -- new password should succeed"
echo "We'll now test authentication with the new password from Vault."
echo "Command:"
echo "NEW_PASSWORD=\$(vault read -field=password \"${CRED_PATH}\")"
echo "ldapwhoami -h \"${LDAP_HOST}:${LDAP_PORT}\" -x -w \"\$NEW_PASSWORD\" -D \"${LDAP_DN}\""
pause
NEW_PASSWORD=$(vault read -field=password "${CRED_PATH}")
if ldapwhoami -h "${LDAP_HOST}:${LDAP_PORT}" -x -w "${NEW_PASSWORD}" -D "${LDAP_DN}"; then
  echo "[OK] New password accepted as expected."
else
  echo "[ERROR] New password did not work!"
  exit 1
fi

announce "Step 7: Updating static role (changing rotation_period)"
echo "Let's update the rotation period for this static role."
echo "Command:"
echo "vault write \"${ROLE_PATH}\" \\"
echo "    dn=\"${LDAP_DN}\" \\"
echo "    username=\"${LDAP_USERNAME}\" \\"
echo "    rotation_period=\"10m\""
pause
vault write "${ROLE_PATH}" \
    dn="${LDAP_DN}" \
    username="${LDAP_USERNAME}" \
    rotation_period="10m"

announce "Step 8: Reading updated static role"
echo "Verify the update by reading the static role again."
echo "Command: vault read \"${ROLE_PATH}\""
pause
vault read "${ROLE_PATH}"

announce "Step 9: Deleting static role"
echo "Cleanup: we will delete the static role."
echo "Command: vault delete \"${ROLE_PATH}\""
pause
vault delete "${ROLE_PATH}"

announce "Step 10: Confirming deletion"
echo "Check that the role is gone."
echo "Command: vault read \"${ROLE_PATH}\""
pause
if vault read "${ROLE_PATH}"; then
  echo "[ERROR] Static role still exists after deletion!"
  exit 1
else
  echo "[OK] Static role deleted successfully."
fi

announce "Demo completed!"