#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail

fail() {
  echo "$1" 1>&2
  exit 1
}

# Required env vars: PLUGIN_PATH, ROTATION_WINDOW
if [[ -z "${PLUGIN_PATH:-}" ]]; then fail "PLUGIN_PATH not set"; fi
if [[ -z "${ROTATION_WINDOW:-}" ]]; then fail "ROTATION_WINDOW not set"; fi

# Compute cron schedule one minute from now
schedule=$(python3 - <<PYTHON
import datetime
now = datetime.datetime.now() + datetime.timedelta(minutes=1)
print(f"{now.minute} {now.hour} * * *")
PYTHON
)
echo "==> Using cron schedule: $schedule"

# Configure plugin for schedule-based rotation
vault write -format=json "${PLUGIN_PATH}/config" \
  disable_automated_rotation=false \
  rotation_schedule="$schedule" \
  rotation_window="${ROTATION_WINDOW}" \
  rotation_period=0 >/dev/null

# Read rotation_schedule from config
rotation_schedule=$(vault read -format=json "${PLUGIN_PATH}/config" | jq -r '.data.rotation_schedule')

# Validate rotation_schedule
if [[ "$rotation_schedule" != "$schedule" ]]; then
  fail "[ERROR] Expected rotation_schedule=$schedule, got $rotation_schedule"
fi

# Read rotation_window from config
rotation_window=$(vault read -format=json "${PLUGIN_PATH}/config" | jq -r '.data.rotation_window')

# Validate rotation_window
if [[ "$rotation_window" != "$ROTATION_WINDOW" ]]; then
  fail "[ERROR] Expected rotation_period=$ROTATION_WINDOW, got $rotation_window"
fi

# Cross-platform parse_epoch helper
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

# Read timestamp before window expiration
before=$(vault read -format=json "${PLUGIN_PATH}/config" | jq -r '.data.last_bind_password_rotation')
before_epoch=$(parse_epoch "$before")

sleep 61 # Wait for the cron job to trigger

# Read timestamp after window expiration
after=$(vault read -format=json "${PLUGIN_PATH}/config" | jq -r '.data.last_bind_password_rotation')
after_epoch=$(parse_epoch "$after")

# Assert a rotation occurred
if [[ "$before" == "null" ]]; then
  echo "[INFO] No previous rotation timestamp found (before=null), first rotation expected."
fi
if [[ "$after" == "null" ]]; then
  fail "[ERROR] No rotation occurred, after=null"
fi

diff=$((after_epoch - before_epoch))
if [[ "$diff" -eq 0 ]]; then
  fail "[ERROR] No rotation occurred at $after"
fi

echo "[OK] Rotation occurred at $after"
