#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0
set -e

# Expect these environment variables:
#   PLUGIN_NAME
#   PLUGIN_DIR

fail() {
  echo "$1" 1>&2
  exit 1
}

[[ -z "$PLUGIN_NAME" ]] && fail "PLUGIN_NAME env variable has not been set"
[[ -z "$PLUGIN_DIR" ]] && fail "PLUGIN_DIR env variable has not been set"

echo "[build] PLUGIN_NAME=${PLUGIN_NAME:-}"
echo "[build] PLUGIN_DIR=${PLUGIN_DIR:-}"

# Remove from project .bin directory if it exists
PROJECT_BIN_DIR="${MAKEFILE_DIR}/bin"
if [ -f "${PROJECT_BIN_DIR}/${PLUGIN_NAME}" ]; then
  echo "[build] Removing existing plugin at ${PROJECT_BIN_DIR}/${PLUGIN_NAME}"
  rm -f "${PROJECT_BIN_DIR}/${PLUGIN_NAME}"
fi

# Ensure destination directory exists
mkdir -p "${PLUGIN_DIR}"

# Remove existing plugin (if present) before copying new one
if [ -f "${PLUGIN_DIR}/${PLUGIN_NAME}" ]; then
  echo "[build] Removing existing plugin at ${PLUGIN_DIR}/${PLUGIN_NAME}"
  rm -f "${PLUGIN_DIR}/${PLUGIN_NAME}"
fi

# Build plugin
pushd "${MAKEFILE_DIR}" >/dev/null
  GOOS="${GOOS:-$(go env GOOS)}"
  GOARCH="${GOARCH:-$(go env GOARCH)}"
  echo "[build] GOOS=${GOOS} GOARCH=${GOARCH}"
  GOOS="${GOOS}" GOARCH="${GOARCH}" make dev
popd >/dev/null

# Copy and set executable bit
cp "${PROJECT_BIN_DIR}/${PLUGIN_NAME}" "${PLUGIN_DIR}/${PLUGIN_NAME}"
chmod +x "${PLUGIN_DIR}/${PLUGIN_NAME}"

# Zip up the plugin binary into a bundle
ZIP_FILE="${PLUGIN_DIR}/${PLUGIN_NAME}.zip"
pushd "${PLUGIN_DIR}" >/dev/null
  zip -j "${ZIP_FILE}" "${PLUGIN_NAME}"
popd >/dev/null

echo "[build] Plugin built and zipped at ${ZIP_FILE}"