#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

set -e

fail() {
  echo "$1" 1>&2
  exit 1
}

[[ -z "$LDAP_DOMAIN" ]] && fail "LDAP_DOMAIN env variable has not been set"
[[ -z "$LDAP_ORG" ]] && fail "LDAP_ORG env variable has not been set"
[[ -z "$LDAP_ADMIN_PW" ]] && fail "LDAP_ADMIN_PW env variable has not been set"
[[ -z "$LDAP_VERSION" ]] && fail "LDAP_VERSION env variable has not been set"
[[ -z "$LDAP_PORT" ]] && fail "LDAP_PORT env variable has not been set"
[[ -z "$LDIF_PATH" ]] && fail "LDIF_PATH env variable has not been set"

LDAP_HOSTNAME="${LDAP_HOSTNAME:-openldap}"

# Pulling image
CONTAINER_CMD="sudo docker"
echo "Pulling image: ${LDAP_DOCKER_NAME}"
LDAP_DOCKER_NAME="docker.io/osixia/openldap:${LDAP_VERSION}"
$CONTAINER_CMD pull "${LDAP_DOCKER_NAME}"

# Run OpenLDAP container
echo "Starting OpenLDAP container..."
$CONTAINER_CMD run -d \
  --name openldap \
  --hostname "${LDAP_HOSTNAME}" \
  -p "${LDAP_PORT}:${LDAP_PORT}" \
  -p 636:636 \
  -e LDAP_ORGANISATION="${LDAP_ORG}" \
  -e LDAP_DOMAIN="${LDAP_DOMAIN}" \
  -e LDAP_ADMIN_PASSWORD="${LDAP_ADMIN_PW}" \
  "${LDAP_DOCKER_NAME}"

echo "OpenLDAP server is now running in Docker!"

# Wait for the container to be up and running
echo "Waiting for OpenLDAP to start..."
sleep 5

# Check container status
status=$(sudo docker ps --filter name=openldap --format "{{.Status}}")
if [[ -n "$status" ]]; then
  echo "OpenLDAP container is running. Status: $status"
else
  echo "OpenLDAP container is NOT running!"
  echo "Check logs with: sudo docker logs openldap"
  exit 1
fi

# Run ldapadd inside the container
sudo docker exec -i openldap ldapadd -x -w "${LDAP_ADMIN_PW}" -D "cn=admin,dc=${LDAP_DOMAIN//./,dc=}" -f /dev/stdin < "${LDIF_PATH}"