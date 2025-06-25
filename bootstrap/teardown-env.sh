#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

set -e

fail() {
  echo "$1" 1>&2
  exit 1
}

[[ -z "$PLUGIN_NAME" ]] && fail "PLUGIN_NAME env variable has not been set"
[[ -z "$PLUGIN_DEST_DIR" ]] && fail "PLUGIN_DEST_DIR env variable has not been set"

MAKEFILE_DIR="${MAKEFILE_DIR:-$(pwd)}"
PROJECT_BIN_DIR="${MAKEFILE_DIR}/bin"

echo "[teardown] Stopping and removing openldap docker container if it exists..."
docker rm -f openldap 2>/dev/null || echo "[teardown] No openldap container found."

# Remove from bin directory
if [ -f "${PROJECT_BIN_DIR}/${PLUGIN_NAME}" ]; then
  echo "[teardown] Removing existing plugin at ${PROJECT_BIN_DIR}/${PLUGIN_NAME}"
  rm -f "${PROJECT_BIN_DIR}/${PLUGIN_NAME}"
fi

# Remove from destination directory
if [ -f "${PLUGIN_DEST_DIR}/${PLUGIN_NAME}" ]; then
  echo "[teardown] Removing existing plugin at ${PLUGIN_DEST_DIR}/${PLUGIN_NAME}"
  rm -f "${PLUGIN_DEST_DIR}/${PLUGIN_NAME}"
fi

echo "[teardown] Teardown complete."