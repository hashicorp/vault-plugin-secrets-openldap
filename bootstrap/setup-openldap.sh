#!/usr/bin/env bash

LDAP_IMAGE="osixia/openldap:1.3.0"
docker pull ${LDAP_IMAGE}

docker run \
  --rm \
  --name=ldap \
  --hostname=ldap \
  --detach \
  -p 389:389 \
  -p 636:636 \
  -e LDAP_ORGANISATION="example" \
  -e LDAP_DOMAIN="example.com" \
  -e LDAP_ADMIN_PASSWORD="adminpassword" \
  ${LDAP_IMAGE}

sleep 5
docker ps --filter name=ldap
ldapadd -x -w "adminpassword" -D "cn=admin,dc=example,dc=com" -f ./ldif/seed.ldif
