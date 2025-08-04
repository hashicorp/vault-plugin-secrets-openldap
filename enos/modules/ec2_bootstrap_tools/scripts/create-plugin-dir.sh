#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

set -e

PLUGIN_DIR="${PLUGIN_DIR:-/etc/vault/plugins}"

sudo mkdir -p "$PLUGIN_DIR"
sudo chown vault:vault "$PLUGIN_DIR"