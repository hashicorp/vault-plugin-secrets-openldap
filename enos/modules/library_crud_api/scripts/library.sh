#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0
set -e

fail() {
  echo "$1" 1>&2
  exit 1
}

# Required environment variables
[[ -z "$PLUGIN_PATH" ]] && fail "PLUGIN_PATH env variable has not been set"
[[ -z "$VAULT_ADDR" ]] && fail "VAULT_ADDR env variable has not been set"
[[ -z "$VAULT_TOKEN" ]] && fail "VAULT_TOKEN env variable has not been set"
[[ -z "$LDAP_HOST" ]] && fail "LDAP_HOST env variable has not been set"
[[ -z "$LDAP_PORT" ]] && fail "LDAP_PORT env variable has not been set"
[[ -z "$LDAP_BASE_DN" ]] && fail "LDAP_BASE_DN env variable has not been set"
[[ -z "$LIBRARY_SET_NAME" ]] && fail "LIBRARY_SET_NAME env variable has not been set"
[[ -z "$SERVICE_ACCOUNT_NAMES" ]] && fail "SERVICE_ACCOUNT_NAMES env variable has not been set"

export VAULT_ADDR
export VAULT_TOKEN

LIB_PATH="${PLUGIN_PATH}/library/${LIBRARY_SET_NAME}"
STATUS_PATH="${LIB_PATH}/status"
CHECKOUT_PATH="${LIB_PATH}/check-out"
CHECKIN_PATH="${LIB_PATH}/check-in"
MANAGE_CHECKIN_PATH="${PLUGIN_PATH}/library/manage/${LIBRARY_SET_NAME}/check-in"

# Verify SERVICE_ACCOUNT_NAMES parsing
IFS=',' read -r -a SA_LIST <<< "$SERVICE_ACCOUNT_NAMES"
if [[ ${#SA_LIST[@]} -lt 1 ]]; then
  fail "SERVICE_ACCOUNT_NAMES must contain at least one account"
fi

# Create library set
echo "==> Creating library set ${LIBRARY_SET_NAME}"
vault write "${LIB_PATH}" \
    service_account_names="${SERVICE_ACCOUNT_NAMES}" \
    ttl="1h" \
    max_ttl="2h" \
    disable_check_in_enforcement=false

# Read library set
echo "==> Reading library set"
vault read "${LIB_PATH}"

# List all library sets and verify ours is present
echo "==> Verifying library set appears in list"
LIST_OUTPUT=$(vault list "${PLUGIN_PATH}/library" 2>/dev/null)
echo "$LIST_OUTPUT" | grep -x "${LIBRARY_SET_NAME}" >/dev/null || fail "Library set '${LIBRARY_SET_NAME}' not found in list"

# Check status
echo "==> Checking library set status"
vault read "${STATUS_PATH}"

# Check out a service account
echo "==> Checking out a service account"
CRED_JSON=$(vault write -format=json "${CHECKOUT_PATH}" ttl="30m")
SA_NAME=$(echo "$CRED_JSON" | jq -r .data.service_account_name)
SA_PW=$(echo "$CRED_JSON" | jq -r .data.password)
LEASE_ID=$(echo "$CRED_JSON" | jq -r .lease_id)

# Validate checkout output
if [[ -z "$SA_NAME" || "$SA_NAME" == "null" ]]; then
  fail "No service_account_name returned from check-out"
fi
if [[ -z "$SA_PW" || "$SA_PW" == "null" ]]; then
  fail "No password returned from check-out"
fi
if [[ -z "$LEASE_ID" || "$LEASE_ID" == "null" ]]; then
  fail "No lease_id returned from check-out"
fi

# Attempt second check-out should fail
echo "==> Verifying no second check-out is allowed"
if vault write -format=json "${CHECKOUT_PATH}" 2>/dev/null; then
  fail "Unexpectedly succeeded second check-out: account wasn't exclusive"
else
  echo "[OK] Second check-out is correctly unavailable"
fi

# Status after checkout
echo "==> Status after check-out"
vault read "${STATUS_PATH}"

# Renew the lease
echo "==> Renewing lease ${LEASE_ID}"
RENEW_JSON=$(vault lease renew -format=json "${LEASE_ID}")
RENEW_TTL=$(echo "$RENEW_JSON" | jq -r .lease_duration)
if [[ -z "$RENEW_TTL" || "$RENEW_TTL" == "null" ]]; then
  fail "Lease renew failed: no lease_duration returned"
fi
# Revoke the lease (auto check-in)
echo "==> Revoking lease ${LEASE_ID} to auto check-in"
vault lease revoke "${LEASE_ID}"
sleep 2
# Verify account available after revoke
echo "==> Verifying account is available after lease revoke"
POST_REVOKE_AVAIL=$(vault read -format=json "${STATUS_PATH}" | jq -r ".data[\"$SA_NAME\"].available")
if [[ "$POST_REVOKE_AVAIL" != "true" ]]; then
  fail "Account '$SA_NAME' should be available after lease revoke"
fi
# Attempt check-in on already available account (should succeed with empty check_ins)
echo "==> Checking in already available account (expect no check_ins)"
CI_JSON=$(vault write -format=json "${CHECKIN_PATH}" service_account_names="${SA_NAME}")
CI_COUNT=$(echo "$CI_JSON" | jq -r '.data.check_ins | length')
if [[ "$CI_COUNT" -ne 0 ]]; then
  fail "Expected 0 check_ins when checking in an already available account, got $CI_COUNT"
fi

# Check the account back in
echo "==> Checking in ${SA_NAME}"
vault write "${CHECKIN_PATH}" service_account_names="${SA_NAME}"

# Status after check-in
echo "==> Status after check-in"
vault read "${STATUS_PATH}"

# Force check-in of all accounts
echo "==> Forcing manage-level check-in of all accounts"
vault write "${MANAGE_CHECKIN_PATH}" service_account_names="${SERVICE_ACCOUNT_NAMES}"

# After force check-in, verify both accounts available
echo "==> Checking status after manage-level check-in"
STATUS_AFTER_MANAGE=$(vault read -format=json "${STATUS_PATH}")
for acct in "${SA_LIST[@]}"; do
  avail=$(echo "$STATUS_AFTER_MANAGE" | jq -r ".data[\"$acct\"].available")
  if [[ "$avail" != "true" ]]; then
    fail "Account '$acct' should be available after manage-level check-in"
  fi
done

# Test TTL expiry automatic check-in
echo "==> Testing TTL expiry automatic check-in"
TTL_TEST_JSON=$(vault write -format=json "${CHECKOUT_PATH}" ttl="10s")
TTL_NAME=$(echo "$TTL_TEST_JSON" | jq -r .data.service_account_name)
echo "Checked out ${TTL_NAME} with 10s TTL, waiting 12s"
sleep 12
POST_TTL_AVAIL=$(vault read -format=json "${STATUS_PATH}" | jq -r ".data[\"$TTL_NAME\"].available")
if [[ "$POST_TTL_AVAIL" != "true" ]]; then
  fail "Account '$TTL_NAME' should be available after TTL expiry"
fi

# Delete library set
echo "==> Deleting library set"
vault delete "${LIB_PATH}"

# Confirm deletion and absence from list
echo "==> Confirming deletion"
if vault read "${LIB_PATH}" 2>/dev/null; then
  fail "Library set still exists after deletion!"
else
  echo "[OK] Library set deleted successfully."
fi
LIST_AFTER_DEL=$(vault list "${PLUGIN_PATH}/library" 2>/dev/null || true)

# Ensure the set no longer appears
if echo "$LIST_AFTER_DEL" | grep -x "${LIBRARY_SET_NAME}" >/dev/null; then
  fail "Library set '${LIBRARY_SET_NAME}' still in list after deletion"
fi
