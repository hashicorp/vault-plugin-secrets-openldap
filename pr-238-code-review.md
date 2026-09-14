# Code Review: PR #238 - Enos Test Infrastructure Refactoring

## Summary

This PR refactors the Enos test infrastructure to support plugin upgrade testing. Main changes: extracted inline bash to dedicated scripts, added plugin management modules, implemented dynamic port allocation for parallel execution, and improved container lifecycle management.

**Critical issues:** Hard-coded sleep in LDAP wait loop, missing error context in curl calls, brittle container name filtering.

**Recommendation:** Fix the sleep-based polling and error handling before merge.

---

## Critical Issues

### Hard-coded sleep will cause flaky tests
**File:** `enos/modules/run_test/scripts/run-blackbox-tests.sh:56`

```bash
sleep "$LDAP_READY_SLEEP_SECONDS"
```

This sleep-based polling is unreliable. LDAP startup time varies with system load. The loop already has retry logic, but the fixed 2-second sleep means tests will either wait too long (wasting CI time) or fail intermittently under load.

Consider exponential backoff or at minimum document why 2 seconds was chosen.

### Missing error context in curl calls
**File:** `enos/modules/manage_plugin/scripts/register-plugin.sh:52-56`

```bash
http_status=$(curl -s -o /dev/null -w "%{http_code}" \
  --header "X-Vault-Token: ${VAULT_TOKEN}" \
  --request PUT \
  --data "{\"sha256\": \"${PLUGIN_SHA256}\", \"command\": \"${PLUGIN_NAME}\"}" \
  "${VAULT_ADDR}/v1/sys/plugins/catalog/secret/${PLUGIN_NAME}")
```

When this fails, you only get the HTTP status code. No response body, no error details. Same issue in `revert-plugin.sh`.

Capture the response body:

```bash
response=$(curl -s -w "\n%{http_code}" \
  --header "X-Vault-Token: ${VAULT_TOKEN}" \
  --request PUT \
  --data "{\"sha256\": \"${PLUGIN_SHA256}\", \"command\": \"${PLUGIN_NAME}\"}" \
  "${VAULT_ADDR}/v1/sys/plugins/catalog/secret/${PLUGIN_NAME}")
http_status=$(echo "$response" | tail -n1)
body=$(echo "$response" | sed '$d')

if [ "${http_status}" != "204" ]; then
  echo "ERROR: plugin catalog registration failed (HTTP ${http_status})"
  echo "Response: $body"
  exit 1
fi
```

### Brittle container name filtering
**File:** `enos/modules/run_test/scripts/run-blackbox-tests.sh:15`

```bash
readonly VAULT_CONTAINER_FILTER="${VAULT_CLUSTER_NAME:-vault-poc}"
```

This filter matches any container with "vault-poc" in the name. If multiple containers exist (e.g., `vault-poc-old`, `vault-poc-test`), `head -1` picks arbitrarily. The script should fail explicitly if multiple matches exist.

```bash
find_container_name() {
  local name_filter="$1"
  local matches
  
  matches=$($CONTAINER_CMD ps -a --filter "name=^${name_filter}$" --format "{{.Names}}")
  local count=$(echo "$matches" | grep -c .)
  
  if [ "$count" -gt 1 ]; then
    echo "ERROR: Multiple containers match filter '$name_filter':" >&2
    echo "$matches" >&2
    return 1
  fi
  
  echo "$matches"
}
```

---

## High Priority Issues

### Port derivation logic is fragile
**File:** `enos/modules/vault_cluster/main.tf:60-65`

```hcl
vault_port = var.vault_port != -1 ? var.vault_port : (
  var.vault_version == "2.0.0"  ? 8199 :
  var.vault_version == "1.21.5" ? 8200 :
  var.vault_version == "1.20.9" ? 8201 :
                                  8202
)
```

This breaks when a new Vault version is added. The default case (8202) will cause port conflicts if two unknown versions run concurrently.

Use a hash-based approach:

```hcl
locals {
  # Generate deterministic port from version string
  version_hash = sum([for c in split("", var.vault_version) : index(split("", "0123456789."), c)])
  vault_port = var.vault_port != -1 ? var.vault_port : 8200 + (local.version_hash % 100)
}
```

Or maintain a map:

```hcl
variable "version_port_map" {
  type = map(number)
  default = {
    "2.0.0"  = 8199
    "1.21.5" = 8200
    "1.20.9" = 8201
    "1.19.x" = 8202
  }
}

locals {
  vault_port = var.vault_port != -1 ? var.vault_port : lookup(
    var.version_port_map,
    var.vault_version,
    8299  # Explicit fallback that won't conflict
  )
}
```

### Missing validation for required environment variables
**File:** `enos/modules/run_test/scripts/run-blackbox-tests.sh:197-202`

```bash
require_env "VAULT_ADDR"
require_env "VAULT_TOKEN"
require_env "REPO_ROOT"
require_env "TEST_PACKAGE"
require_env "TEST_TIMEOUT"
```

Good that you validate these, but `VAULT_CLUSTER_NAME` is also required (used at line 15) and isn't validated. Add it to the list.

### Inconsistent error handling in wait loops
**File:** `enos/modules/run_test/scripts/run-blackbox-tests.sh:145-167`

The Vault container health check returns 1 on failure, but the LDAP wait loop (line 48-62) returns 1 without checking if it's actually an error or just a timeout. Both should be consistent.

```bash
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
  echo "Last ldapsearch output:"
  ldapsearch -x -H "$LDAP_URL_PUBLIC" -b "$LDAP_BASE_DN" -D "$LDAP_BIND_DN" -w "$LDAP_BIND_PASS" 2>&1 || true
  return 1
}
```

---

## Medium Priority Issues

### Unnecessary chmod after build
**File:** `enos/modules/stage_candidate_plugin/main.tf:53`

```hcl
"chmod +x '${var.plugin_dir}/${var.plugin_name}'"
```

Go binaries are already executable after build. This is redundant unless you're working around a specific filesystem issue. If it's needed, document why.

### Hard-coded LDIF in script
**File:** `enos/modules/run_test/scripts/run-blackbox-tests.sh:73-133`

The LDIF is embedded directly in the script. This makes it hard to maintain and test independently. Extract to a separate file:

```bash
seed_ldap_data() {
  log_section "Initializing LDAP organizational units"
  wait_for_ldap
  
  log_section "Creating organizational units and test users"
  ldapadd -x -H "$LDAP_URL_PUBLIC" -D "$LDAP_BIND_DN" -w "$LDAP_BIND_PASS" \
    -f "${REPO_ROOT}/enos/modules/run_test/testdata/seed.ldif" || true
  echo "LDAP initialization complete"
}
```

Then create `enos/modules/run_test/testdata/seed.ldif` with the LDIF content.

### Inconsistent quoting in shell scripts
**File:** `enos/modules/run_test/scripts/run-blackbox-tests.sh:33`

```bash
$CONTAINER_CMD ps -a --filter "name=$name_filter" --format "{{.Names}}" | head -1
```

`$CONTAINER_CMD` is unquoted but `$name_filter` is quoted. Be consistent:

```bash
"$CONTAINER_CMD" ps -a --filter "name=$name_filter" --format "{{.Names}}" | head -1
```

### Missing cleanup on script failure
**File:** `enos/modules/run_test/scripts/run-blackbox-tests.sh:70`

```bash
tmp_ldif=$(mktemp)
```

If the script exits early (e.g., ldapadd fails), the temp file leaks. Add a trap:

```bash
seed_ldap_data() {
  local tmp_ldif
  
  log_section "Initializing LDAP organizational units"
  wait_for_ldap
  
  log_section "Creating organizational units and test users"
  tmp_ldif=$(mktemp)
  trap "rm -f '$tmp_ldif'" EXIT
  
  cat <<'EOF' > "$tmp_ldif"
  # ... LDIF content ...
EOF
  
  ldapadd -x -H "$LDAP_URL_PUBLIC" -D "$LDAP_BIND_DN" -w "$LDAP_BIND_PASS" -f "$tmp_ldif" || true
  rm -f "$tmp_ldif"
  trap - EXIT
  echo "LDAP initialization complete"
}
```

---

## Low Priority Issues

### Comment formatting inconsistency
**File:** `enos/modules/vault_cluster/main.tf:102-105`

```hcl
# Do NOT request IPC_LOCK. GitHub Actions runners use rootless Podman, which
# cannot grant this capability; the container crashes immediately when the
# kernel rejects the mlock(2) syscall. VAULT_DISABLE_MLOCK=true makes Vault
# skip mlock altogether, which is safe in ephemeral test containers.
```

This is a 4-line comment block. Most other comments in the file are single-line or use the `#` prefix consistently. Consider breaking into multiple single-line comments for consistency with the rest of the codebase.

### Verbose logging could be configurable
**File:** `enos/modules/run_test/scripts/run-blackbox-tests.sh:217-223`

```bash
log_section "Container Status"
$CONTAINER_CMD ps -a

log_section "Finding Vault container (including exited)"
# ...
log_section "Vault container logs"
$CONTAINER_CMD logs "$vault_container" 2>&1
```

This dumps a lot of output on every test run. Consider adding a `VERBOSE` or `DEBUG` environment variable to control this.

### Magic number for shared memory
**File:** `enos/modules/vault_cluster/main.tf:153-155`

```hcl
# 128 MiB of shared memory prevents OOM-related crashes observed under
# resource contention when four matrix variants run concurrently.
shm_size = 128
```

Good comment explaining why, but 128 is a magic number. Make it a variable with a default:

```hcl
variable "shm_size_mb" {
  description = "Shared memory size in MiB. 128 MiB prevents OOM crashes under resource contention."
  type        = number
  default     = 128
}
```

---

## Positive Observations

### Excellent script structure
The new `run-blackbox-tests.sh` is well-organized with clear functions, constants at the top, and a main() entry point. Much better than the inline heredoc it replaces.

### Good separation of concerns
The new `manage_plugin` and `stage_candidate_plugin` modules cleanly separate plugin lifecycle management from test execution. This makes the upgrade scenario much easier to understand.

### Proper use of readonly
Constants like `LDAP_BASE_DN` and `CONTAINER_CMD` are marked readonly, preventing accidental modification.

### Comprehensive comments
The register-plugin.sh and revert-plugin.sh scripts have excellent header comments explaining the design and how Vault's two-tier plugin registry works.

---

## Questions for Author

1. **Port allocation:** Have you tested what happens when more than 4 Vault versions run concurrently? The current scheme only allocates 4 ports (8199-8202).

2. **LDAP seed data:** The `|| true` on line 135 silently ignores ldapadd failures. Is this intentional for idempotency, or should it fail if the initial seed fails?

3. **Container restart policy:** Why change from `unless-stopped` to `no`? The comment says "so terraform destroy can cleanly remove them" but Docker should handle that regardless. Is this working around a specific issue?

4. **Plugin directory permissions:** The bind-mount is read_only=false. Do the tests need to write to this directory, or is this just for the initial plugin registration?

---

## Recommendations

1. **Fix the sleep-based polling** - Replace with exponential backoff or at minimum document the timing assumptions
2. **Add error context to curl calls** - Capture response bodies for debugging
3. **Make container filtering more robust** - Fail explicitly on multiple matches
4. **Extract LDIF to separate file** - Easier to maintain and test
5. **Add VAULT_CLUSTER_NAME validation** - It's required but not checked
6. **Consider hash-based port allocation** - More maintainable than version-specific mapping

After addressing the critical and high-priority issues, this is a solid refactoring that significantly improves the test infrastructure's maintainability.
