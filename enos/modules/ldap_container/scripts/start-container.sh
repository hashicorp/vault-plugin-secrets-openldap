#!/usr/bin/env bash
set -euo pipefail

CONTAINER_CMD="docker"

echo "Using container runtime: ${CONTAINER_CMD}"

# Stop and remove existing container if it exists
if ${CONTAINER_CMD} ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "Removing existing container: ${CONTAINER_NAME}"
    ${CONTAINER_CMD} stop "${CONTAINER_NAME}" || true
    ${CONTAINER_CMD} rm "${CONTAINER_NAME}" || true
fi

# Start OpenLDAP container
echo "Starting OpenLDAP container: ${CONTAINER_NAME}"
${CONTAINER_CMD} run -d \
    --name "${CONTAINER_NAME}" \
    --network "${NETWORK_NAME}" \
    -p "0.0.0.0:${LDAP_PORT}:389" \
    -e LDAP_ORGANISATION="Example Inc." \
    -e LDAP_DOMAIN="example.com" \
    -e LDAP_ADMIN_PASSWORD="adminpassword" \
    osixia/openldap:1.5.0

# Wait for LDAP to be ready
echo "Waiting for LDAP to be ready..."
max_attempts=30
attempt=0
while [ $attempt -lt $max_attempts ]; do
    if ${CONTAINER_CMD} exec "${CONTAINER_NAME}" ldapsearch -x -H ldap://localhost -b "dc=example,dc=com" -D "cn=admin,dc=example,dc=com" -w adminpassword &> /dev/null; then
        echo "LDAP is ready!"
        exit 0
    fi
    attempt=$((attempt + 1))
    echo "Waiting for LDAP... (attempt $attempt/$max_attempts)"
    sleep 2
done

echo "Error: LDAP failed to become ready"
${CONTAINER_CMD} logs "${CONTAINER_NAME}"
exit 1
