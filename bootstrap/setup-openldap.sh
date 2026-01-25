#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

set -e

fail() {
  echo "$1" 1>&2
  exit 1
}

[[ -z "$LDAP_DOMAIN" ]] && fail "LDAP_DOMAIN env variable has not been set"
[[ -z "$LDAP_ORG" ]] && fail "LDAP_ORG env variable has not been set"
[[ -z "$LDAP_ADMIN_PW" ]] && fail "LDAP_ADMIN_PW env variable has not been set"
[[ -z "$IMAGE_TAG" ]] && fail "IMAGE_TAG env variable has not been set"
[[ -z "$LDAP_PORT" ]] && fail "LDAP_PORT env variable has not been set"
[[ -z "$LDIF_PATH" ]] && fail "LDIF_PATH env variable has not been set"

LDAP_HOSTNAME="${LDAP_HOSTNAME:-openldap}"

# Determine container runtime: prefer podman if installed, allow override via CONTAINER_RUNTIME
if [[ -n "$CONTAINER_RUNTIME" ]]; then
  RUNTIME="$CONTAINER_RUNTIME"
elif command -v podman >/dev/null 2>&1; then
  RUNTIME="sudo podman"
else
  RUNTIME="sudo docker"
fi

echo "Using container runtime: $RUNTIME"

# Pulling image
echo "Pulling image: ${LDAP_DOCKER_NAME}"
LDAP_DOCKER_NAME="docker.io/osixia/openldap:${IMAGE_TAG}"
${RUNTIME} pull "${LDAP_DOCKER_NAME}"

# Run OpenLDAP container
echo "Starting OpenLDAP container..."
${RUNTIME} run -d \
  --name openldap \
  --hostname "${LDAP_HOSTNAME}" \
  -p "${LDAP_PORT}:${LDAP_PORT}" \
  -p 1636:636 \
  -e LDAP_ORGANISATION="${LDAP_ORG}" \
  -e LDAP_DOMAIN="${LDAP_DOMAIN}" \
  -e LDAP_ADMIN_PASSWORD="${LDAP_ADMIN_PW}" \
  "${LDAP_DOCKER_NAME}"

echo "OpenLDAP server is now running in container!"

# Wait for the container to be up and running
echo "Waiting for OpenLDAP to start..."
sleep 5

# Check container status
status=$(${RUNTIME} ps --filter name=openldap --format "{{.Status}}")
if [[ -n "$status" ]]; then
  echo "OpenLDAP container is running. Status: $status"
else
  echo "OpenLDAP container is NOT running!"
  echo "Check logs with: ${RUNTIME} logs openldap"
  exit 1
fi

# Run ldapadd inside the container
${RUNTIME} exec -i openldap ldapadd -x -w "${LDAP_ADMIN_PW}" -D "cn=admin,dc=${LDAP_DOMAIN//./,dc=}" -f /dev/stdin < "${LDIF_PATH}"
