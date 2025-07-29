#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

set -e

# Function to detect the OS
detect_os() {
  if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    echo "$ID"
  else
    echo "unknown"
  fi
}

# Function to install shasum or sha1sum
install_shasum() {
  OS_ID=$(detect_os)

  case "$OS_ID" in
    ubuntu|debian)
      sudo apt-get update
      sudo apt-get install -y perl
      ;;
    amzn|amazon)
      sudo yum install -y perl-Digest-SHA
      ;;
    rhel|centos|fedora)
      sudo yum install -y perl-Digest-SHA
      ;;
    alpine)
      sudo apk add --no-cache perl
      ;;
    *)
      echo "Unsupported OS: $OS_ID"
      exit 1
      ;;
  esac

  # Verify installation
  if ! command -v shasum >/dev/null 2>&1 && ! command -v sha1sum >/dev/null 2>&1; then
    echo "Failed to install shasum or sha1sum"
    exit 1
  fi
}

install_shasum