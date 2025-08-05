#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

set -e

# All of these environment variables are required or an error will be returned.
[ "${BIND_DN:?}" ]
[ "${BIND_PASSWORD:?}" ]
[ "${LDAP_URL:?}" ]
[ "${USER_DN:?}" ]
[ "${GROUP:?}" ]

for i in $(seq 0 9); do

  USER="USER${i}"

  # create the seed ldif
  cat >> seed.ldif <<EOF
dn: racfid=${USER},${USER_DN}
objectClass: racfUser
racfid: ${USER}
racfPassPhrase: initialracfpassphrase1234
racfdefaultgroup: ${GROUP}
racfowner: ${GROUP}

EOF

  # create the cleanup ldif
  cat >> cleanup.ldif <<EOF
dn: racfid=${USER},${USER_DN}
changetype: delete

EOF

done

ldapadd -x -D "${BIND_DN}" -w "${BIND_PASSWORD}" \
  -H "${LDAP_URL}" -f ./seed.ldif
