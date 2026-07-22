#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail

fail() {
  echo "$1" 1>&2
  exit 1
}

# Required env vars: PLUGIN_PATH, ROTATION_PERIOD
if [[ -z "${PLUGIN_PATH:-}" ]]; then fail "PLUGIN_PATH not set"; fi
if [[ -z "${ROTATION_PERIOD:-}" ]]; then fail "ROTATION_PERIOD not set"; fi

# Configure plugin for rotation period
vault write -format=json "${PLUGIN_PATH}/config" \
  disable_automated_rotation=false \
  rotation_period="${ROTATION_PERIOD}" \
  rotation_schedule="" \
  rotation_window=0 >/dev/null

# Add cross-platform parse_epoch helper
parse_epoch() {
  python3 -c "
import sys, datetime, re
ts = sys.argv[1]
if ts == 'null':
    print(0)
    sys.exit(0)
# Remove Z and handle nanoseconds
if ts.endswith('Z'):
    ts = ts[:-1]
match = re.match(r'(.*\.\d{6})\d*(.*)', ts)
if match:
    ts = match.group(1) + match.group(2)
dt = datetime.datetime.fromisoformat(ts)
print(int(dt.timestamp()))
" "$1"
}

# Read rotation_period from config
rotation_period=$(vault read -format=json "${PLUGIN_PATH}/config" | jq -r '.data.rotation_period')

# Validate rotation_period
if [[ "$rotation_period" != "$ROTATION_PERIOD" ]]; then
  fail "[ERROR] Expected rotation_period=$ROTATION_PERIOD, got $rotation_period"
fi

# Read timestamp before rotation
before=$(vault read -format=json "${PLUGIN_PATH}/config" | jq -r '.data.last_bind_password_rotation')

# Convert to epoch
before_epoch=$(parse_epoch "$before")

# Wait for rotation_period + 1 seconds
echo "==> Sleeping for $((ROTATION_PERIOD + 1)) seconds for automated rotation"
sleep $((ROTATION_PERIOD + 1))

# Read timestamp after rotation
after=$(vault read -format=json "${PLUGIN_PATH}/config" | jq -r '.data.last_bind_password_rotation')

after_epoch=$(parse_epoch "$after")

# Assert a rotation occurred
if [[ "$before" == "null" ]]; then
  echo "[INFO] No previous rotation timestamp found (before=null), first rotation expected."
fi
if [[ "$after" == "null" ]]; then
  fail "[ERROR] No rotation occurred, after=null"
fi

# Compute difference
diff=$((after_epoch - before_epoch))
if [[ "$diff" -lt "$ROTATION_PERIOD" ]]; then
  fail "[ERROR] Automated rotation did not occur: delta $diff < $ROTATION_PERIOD"
fi

#final check:

echo "[OK] Automated rotation succeeded: delta $diff >= $ROTATION_PERIOD"
