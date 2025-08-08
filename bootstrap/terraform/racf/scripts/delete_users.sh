#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

set -e

# All of these environment variables are required or an error will be returned.
[ "${BIND_DN:?}" ]
[ "${BIND_PASSWORD:?}" ]
[ "${LDAP_URL:?}" ]

ldapmodify -x -D "${BIND_DN}" -w "${BIND_PASSWORD}" \
  -H "${LDAP_URL}" -f ./cleanup.ldif

rm seed.ldif || true
rm cleanup.ldif || true

