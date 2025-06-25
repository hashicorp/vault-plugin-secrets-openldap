#!/bin/bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

set -e

if [[ -z "$VAULT_ADDR" || -z "$UNSEAL_KEYS" || -z "$THRESHOLD" ]]; then
  echo "Usage: $0 <vault_addr> <keys_comma_separated> <threshold>"
  exit 1
fi

IFS=',' read -ra KEYS <<< "$UNSEAL_KEYS"

export VAULT_ADDR

for ((i=0; i<THRESHOLD; i++)); do
  key="${KEYS[$i]}"
  echo "Unsealing with key #$((i+1))..."
  vault operator unseal "$key"
done

echo "Vault unseal attempted with $THRESHOLD keys."