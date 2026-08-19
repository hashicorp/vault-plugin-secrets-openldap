#!/usr/bin/env bash
set -euo pipefail

readonly LDAP_BASE_DN="dc=enos,dc=com"
readonly LDAP_READY_ATTEMPTS=30
readonly LDAP_READY_SLEEP_SECONDS=2
readonly SERVICE_READY_ATTEMPTS=60
readonly SERVICE_READY_SLEEP_SECONDS=2
readonly VAULT_API_ATTEMPTS=30
readonly VAULT_API_SLEEP_SECONDS=2
readonly CONTAINER_CMD="docker"

# VAULT_CLUSTER_NAME is injected by the run_test module (set to the cluster_name
# variable) so the filter matches exactly this scenario variant's container.
readonly VAULT_CONTAINER_FILTER="${VAULT_CLUSTER_NAME:-vault-poc}"

require_env() {
  local name="$1"

  if [ -z "${!name:-}" ]; then
    echo "ERROR: required environment variable '$name' is not set"
    exit 1
  fi
}

log_section() {
  echo "=== $1 ==="
}

find_container_name() {
  local name_filter="$1"

  $CONTAINER_CMD ps -a --filter "name=$name_filter" --format "{{.Names}}" | head -1
}

container_status() {
  local container_name="$1"

  $CONTAINER_CMD inspect "$container_name" --format='{{.State.Status}}' 2>/dev/null || echo "unknown"
}

container_health() {
  local container_name="$1"

  $CONTAINER_CMD inspect "$container_name" --format='{{.State.Health.Status}}' 2>/dev/null || echo "none"
}

wait_for_ldap() {
  local attempt

  for attempt in $(seq 1 "$LDAP_READY_ATTEMPTS"); do
    if ldapsearch -x -H "$LDAP_URL_PUBLIC" -b "$LDAP_BASE_DN" -D "$LDAP_BIND_DN" -w "$LDAP_BIND_PASS" &>/dev/null; then
      echo "LDAP is ready at attempt $attempt"
      return 0
    fi

    echo "Waiting for LDAP... (attempt $attempt/$LDAP_READY_ATTEMPTS)"
    sleep "$LDAP_READY_SLEEP_SECONDS"
  done

  echo "ERROR: LDAP did not become ready after $LDAP_READY_ATTEMPTS attempts"
  return 1
}

seed_ldap_data() {
  local tmp_ldif

  log_section "Initializing LDAP organizational units"
  wait_for_ldap

  log_section "Creating organizational units and test users"
  tmp_ldif=$(mktemp)

  cat <<'EOF' > "$tmp_ldif"
dn: ou=users,dc=enos,dc=com
objectClass: organizationalUnit
ou: users

dn: ou=groups,dc=enos,dc=com
objectClass: organizationalUnit
ou: groups

dn: uid=enos,ou=users,dc=enos,dc=com
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: enos
cn: Enos User
sn: User
userPassword: password
uidNumber: 10000
gidNumber: 10000
homeDirectory: /home/enos

dn: uid=svc-account-1,ou=users,dc=enos,dc=com
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: svc-account-1
cn: Service Account 1
sn: Account
userPassword: password
uidNumber: 10001
gidNumber: 10000
homeDirectory: /home/svc-account-1

dn: uid=svc-account-2,ou=users,dc=enos,dc=com
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: svc-account-2
cn: Service Account 2
sn: Account
userPassword: password
uidNumber: 10002
gidNumber: 10000
homeDirectory: /home/svc-account-2

dn: uid=svc-delete,ou=users,dc=enos,dc=com
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: svc-delete
cn: Service Delete Account
sn: Account
userPassword: password
uidNumber: 10003
gidNumber: 10000
homeDirectory: /home/svc-delete
EOF

  ldapadd -x -H "$LDAP_URL_PUBLIC" -D "$LDAP_BIND_DN" -w "$LDAP_BIND_PASS" -f "$tmp_ldif" || true
  rm -f "$tmp_ldif"
  echo "LDAP initialization complete"
}

wait_for_vault_container_health() {
  local vault_container="$1"
  local attempt
  local status

  # Gate only on the container process being alive. Vault readiness is verified
  # separately by wait_for_vault_api which polls /v1/sys/health directly.
  # Waiting for Docker's health=healthy is unreliable under resource contention:
  # when 4 parallel matrix variants start simultaneously the daemon can delay
  # healthcheck probes past the start_period, leaving the container stuck in
  # "starting" indefinitely even though Vault is fully operational.
  log_section "Waiting for Vault container to be running"
  for attempt in $(seq 1 "$SERVICE_READY_ATTEMPTS"); do
    status=$(container_status "$vault_container")

    echo "Attempt $attempt/$SERVICE_READY_ATTEMPTS: Container=$status"

    if [ "$status" = "running" ]; then
      echo "Container is running."
      return 0
    fi

    if [ "$status" = "exited" ] || [ "$status" = "dead" ]; then
      echo "ERROR: Container stopped unexpectedly (status: $status)"
      $CONTAINER_CMD logs "$vault_container" 2>&1 | tail -50
      return 1
    fi

    sleep "$SERVICE_READY_SLEEP_SECONDS"
  done

  echo "ERROR: Vault container did not reach running state after $SERVICE_READY_ATTEMPTS attempts"
  return 1
}

wait_for_vault_api() {
  local attempt

  log_section "Waiting for Vault API"
  for attempt in $(seq 1 "$VAULT_API_ATTEMPTS"); do
    if curl -sf "$VAULT_ADDR/v1/sys/health" > /dev/null 2>&1; then
      echo "Vault API is responding at attempt $attempt"
      return 0
    fi

    echo "API check attempt $attempt/$VAULT_API_ATTEMPTS..."
    sleep "$VAULT_API_SLEEP_SECONDS"
  done

  echo "ERROR: Vault API did not become ready after $VAULT_API_ATTEMPTS attempts"
  return 1
}

run_blackbox_tests() {
  log_section "Running tests"
  export PATH="$(go env GOROOT)/bin:$PATH"
  go test -v -tags=blackbox -timeout="$TEST_TIMEOUT" "$TEST_PACKAGE"
}

main() {
  require_env "VAULT_ADDR"
  require_env "VAULT_TOKEN"
  require_env "REPO_ROOT"
  require_env "TEST_PACKAGE"
  require_env "TEST_TIMEOUT"

  cd "$REPO_ROOT"

  if [ -n "${LDAP_URL_PUBLIC:-}" ]; then
    require_env "LDAP_BIND_DN"
    require_env "LDAP_BIND_PASS"
    seed_ldap_data
  fi

  log_section "Container Status"
  $CONTAINER_CMD ps -a

  log_section "Finding Vault container (including exited)"
  local vault_container
  vault_container=$(find_container_name "$VAULT_CONTAINER_FILTER")
  if [ -z "$vault_container" ]; then
    echo "ERROR: No Vault container found at all!"
    exit 1
  fi
  echo "Found Vault container: $vault_container"

  log_section "Vault container logs"
  $CONTAINER_CMD logs "$vault_container" 2>&1

  log_section "Vault container inspection"
  $CONTAINER_CMD inspect "$vault_container" | jq '.[] | {State: .State, Config: {Env: .Config.Env, Cmd: .Config.Cmd}}'

  if [ "$(container_status "$vault_container")" != "running" ]; then
    echo "ERROR: Container is not running (status: $(container_status "$vault_container"))"
    echo "Container exited. This is a container startup issue, not a test issue."
    exit 1
  fi

  wait_for_vault_container_health "$vault_container"
  wait_for_vault_api
  run_blackbox_tests
}

main "$@"
