#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1
set -e

# Expect these environment variables:
#   PLUGIN_SOURCE_TYPE: 'local_build', 'registry', 'local_path'
#   PLUGIN_NAME
#   PLUGIN_DEST_DIR
#   (for local_build)
#       MAKEFILE_DIR (where Makefile is located, or use $PWD)
#   (for registry)
#       PLUGIN_REGISTRY_URL
#   (for local_path)
#       PLUGIN_LOCAL_PATH (full path to existing plugin binary)

# Detect GOOS
detect_goos() {
  local uname_os
  uname_os=$(uname -s)
  case "$uname_os" in
    Linux*)   echo "linux" ;;
    Darwin*)  echo "darwin" ;;
    FreeBSD*) echo "freebsd" ;;
    CYGWIN*|MINGW*|MSYS*) echo "windows" ;;
    *)        echo "unknown" ;;
  esac
}

# Detect GOARCH
detect_goarch() {
  local arch
  arch=$(uname -m)
  case "$arch" in
    x86_64)   echo "amd64" ;;
    arm64|aarch64) echo "arm64" ;;
    armv7l)   echo "arm" ;;
    i386|i686) echo "386" ;;
    *)        echo "unknown" ;;
  esac
}

fail() {
  echo "$1" 1>&2
  exit 1
}

[[ -z "$PLUGIN_SOURCE_TYPE" ]] && fail "PLUGIN_SOURCE_TYPE env variable has not been set"
[[ -z "$PLUGIN_NAME" ]] && fail "PLUGIN_NAME env variable has not been set"
[[ -z "$PLUGIN_DEST_DIR" ]] && fail "PLUGIN_DEST_DIR env variable has not been set"

echo "[build] PLUGIN_SOURCE_TYPE=${PLUGIN_SOURCE_TYPE:-}"
echo "[build] PLUGIN_NAME=${PLUGIN_NAME:-}"
echo "[build] PLUGIN_DEST_DIR=${PLUGIN_DEST_DIR:-}"

# Remove from project .bin directory if it exists
PROJECT_BIN_DIR="${MAKEFILE_DIR}/bin"
if [ -f "${PROJECT_BIN_DIR}/${PLUGIN_NAME}" ]; then
  echo "[build] Removing existing plugin at ${PROJECT_BIN_DIR}/${PLUGIN_NAME}"
  rm -f "${PROJECT_BIN_DIR}/${PLUGIN_NAME}"
fi

# Ensure destination directory exists
mkdir -p "${PLUGIN_DEST_DIR}"

# Remove existing plugin (if present) before copying new one
if [ -f "${PLUGIN_DEST_DIR}/${PLUGIN_NAME}" ]; then
  echo "[build] Removing existing plugin at ${PLUGIN_DEST_DIR}/${PLUGIN_NAME}"
  rm -f "${PLUGIN_DEST_DIR}/${PLUGIN_NAME}"
fi

case "${PLUGIN_SOURCE_TYPE}" in
  local_build)
    : "${MAKEFILE_DIR:?MAKEFILE_DIR is required for local_build}"
    echo "[build] Building with make dev in $MAKEFILE_DIR"
    pushd "$MAKEFILE_DIR"
    # Use env vars if set, otherwise detect
    if [ -z "$GOOS" ]; then
      GOOS=$(detect_goos)
    fi
    if [ -z "$GOARCH" ]; then
      GOARCH=$(detect_goarch)
    fi
    echo "[build] Using GOOS=$GOOS GOARCH=$GOARCH"
    GOOS="$GOOS" GOARCH="$GOARCH" make dev
    popd
    cp "${PROJECT_BIN_DIR}/${PLUGIN_NAME}" "${PLUGIN_DEST_DIR}/${PLUGIN_NAME}"
    chmod +x "${PLUGIN_DEST_DIR}/${PLUGIN_NAME}"
    ;;

  registry)
    : "${PLUGIN_REGISTRY_URL:?PLUGIN_REGISTRY_URL is required for registry source}"
    echo "[build] Downloading from registry: $PLUGIN_REGISTRY_URL"
    curl -fLo "${PLUGIN_DEST_DIR}/${PLUGIN_NAME}" "$PLUGIN_REGISTRY_URL"
    chmod +x "${PLUGIN_DEST_DIR}/${PLUGIN_NAME}"
    ;;

  local_path)
    : "${PLUGIN_LOCAL_PATH:?PLUGIN_LOCAL_PATH is required for local_path source}"
    echo "[build] Copying from local path: $PLUGIN_LOCAL_PATH"
    cp "${PLUGIN_LOCAL_PATH}" "${PLUGIN_DEST_DIR}/${PLUGIN_NAME}"
    chmod +x "${PLUGIN_DEST_DIR}/${PLUGIN_NAME}"
    ;;

  *)
    echo "[build] ERROR: Unknown PLUGIN_SOURCE_TYPE: ${PLUGIN_SOURCE_TYPE}"
    exit 1
    ;;
esac

echo "[build] Plugin binary is at ${PLUGIN_DEST_DIR}/${PLUGIN_NAME}"