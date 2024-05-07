# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

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

# Sets up the binary with local changes
vault plugin register \
    -sha256="$(shasum -a 256 "$PLUGIN_DIR"/"$PLUGIN_NAME" | awk '{print $1}')" \
    -version="0.0.1" \
    secret "${PLUGIN_NAME}"

if [ -e scripts/custom.sh ]
then
  . scripts/custom.sh
fi

