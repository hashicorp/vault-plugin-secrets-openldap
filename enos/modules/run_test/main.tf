terraform {
  required_providers {
    enos = {
      source = "registry.terraform.io/hashicorp-forge/enos"
    }
  }
}

variable "vault_address" {
  description = "Vault API address"
  type        = string
}

variable "vault_token" {
  description = "Vault root token"
  type        = string
  sensitive   = true
}

variable "test_package" {
  description = "Go test package path relative to repository root"
  type        = string
}

variable "repo_root" {
  description = "Repository root directory"
  type        = string
}

variable "test_timeout" {
  description = "Test timeout"
  type        = string
  default     = "10m"
}

variable "ldap_url_private" {
  description = "LDAP URL (private/container network)"
  type        = string
  default     = ""
}

variable "ldap_url_public" {
  description = "LDAP URL (public/host network)"
  type        = string
  default     = ""
}

variable "ldap_bind_dn" {
  description = "LDAP bind DN"
  type        = string
  default     = ""
}

variable "ldap_bind_pass" {
  description = "LDAP bind password"
  type        = string
  sensitive   = true
  default     = ""
}

variable "ldap_username" {
  description = "LDAP username for tests"
  type        = string
  default     = "enos"
}

variable "ldap_admin_pw" {
  description = "LDAP admin password"
  type        = string
  sensitive   = true
  default     = ""
}

resource "enos_local_exec" "test" {
  environment = {
    VAULT_ADDR        = var.vault_address
    VAULT_TOKEN       = var.vault_token
    LDAP_URL_PRIVATE  = var.ldap_url_private
    LDAP_URL_PUBLIC   = var.ldap_url_public
    LDAP_BIND_DN      = var.ldap_bind_dn
    LDAP_BIND_PASS    = var.ldap_bind_pass
    LDAP_USERNAME     = var.ldap_username
    LDAP_ADMIN_PW     = var.ldap_admin_pw
  }

  inline = [
    <<-EOT
    cd ${var.repo_root}
    
    # Initialize LDAP organizational units if LDAP is configured
    if [ -n "${var.ldap_url_public}" ]; then
      echo "=== Initializing LDAP organizational units ==="
      
      # Extract host and port from LDAP URL
      LDAP_HOST=$(echo "${var.ldap_url_public}" | sed 's|ldap://||' | cut -d: -f1)
      LDAP_PORT=$(echo "${var.ldap_url_public}" | sed 's|ldap://||' | cut -d: -f2)
      
      # Wait for LDAP to be ready
      for i in {1..30}; do
        if ldapsearch -x -H "${var.ldap_url_public}" -b "dc=enos,dc=com" -D "${var.ldap_bind_dn}" -w "${var.ldap_bind_pass}" &>/dev/null; then
          echo "LDAP is ready at attempt $i"
          break
        fi
        echo "Waiting for LDAP... (attempt $i/30)"
        sleep 2
      done
      
      # Create organizational units and test users (ignore errors if they already exist)
      echo "Creating organizational units and test users..."
      ldapadd -x -H "${var.ldap_url_public}" -D "${var.ldap_bind_dn}" -w "${var.ldap_bind_pass}" <<-LDIF || true
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
 LDIF
      
      echo "LDAP initialization complete"
    fi
    
    CONTAINER_CMD="docker"
    
    echo "=== DEBUG: Container Status ==="
    $CONTAINER_CMD ps -a
    
    echo "=== DEBUG: Finding Vault container (including exited) ==="
    VAULT_CONTAINER=$($CONTAINER_CMD ps -a --filter "name=vault-poc" --format "{{.Names}}" | head -1)
    
    if [ -z "$VAULT_CONTAINER" ]; then
      echo "ERROR: No Vault container found at all!"
      exit 1
    fi
    
    echo "Found Vault container: $VAULT_CONTAINER"
    
    echo "=== DEBUG: Vault container logs ==="
    $CONTAINER_CMD logs "$VAULT_CONTAINER" 2>&1
    
    echo "=== DEBUG: Vault container inspection ==="
    $CONTAINER_CMD inspect "$VAULT_CONTAINER" | jq '.[] | {State: .State, Config: {Env: .Config.Env, Cmd: .Config.Cmd}}'
    
    echo "=== DEBUG: Checking container status ==="
    CONTAINER_STATUS=$($CONTAINER_CMD inspect "$VAULT_CONTAINER" --format='{{.State.Status}}' 2>/dev/null || echo "unknown")
    
    if [ "$CONTAINER_STATUS" != "running" ]; then
      echo "ERROR: Container is not running (status: $CONTAINER_STATUS)"
      echo "Container exited. This is a container startup issue, not a test issue."
      exit 1
    fi
    
    echo "=== DEBUG: Waiting for container health ==="
    for i in {1..60}; do
      HEALTH_STATUS=$($CONTAINER_CMD inspect "$VAULT_CONTAINER" --format='{{.State.Health.Status}}' 2>/dev/null || echo "none")
      CONTAINER_STATUS=$($CONTAINER_CMD inspect "$VAULT_CONTAINER" --format='{{.State.Status}}' 2>/dev/null || echo "unknown")
      
      echo "Attempt $i/60: Container=$CONTAINER_STATUS, Health=$HEALTH_STATUS"
      
      if [ "$CONTAINER_STATUS" = "running" ] && [ "$HEALTH_STATUS" = "healthy" ]; then
        echo "Container is healthy!"
        break
      fi
      
      if [ "$CONTAINER_STATUS" != "running" ]; then
        echo "ERROR: Container stopped running!"
        $CONTAINER_CMD logs "$VAULT_CONTAINER" 2>&1 | tail -50
        exit 1
      fi
      
      sleep 2
    done
    
    echo "=== DEBUG: Waiting for Vault API ==="
    for i in {1..30}; do
      if curl -sf ${var.vault_address}/v1/sys/health > /dev/null 2>&1; then
        echo "Vault API is responding at attempt $i"
        break
      fi
      echo "API check attempt $i/30..."
      sleep 2
    done
    
    echo "=== DEBUG: Checking LDAP container ==="
    LDAP_CONTAINER=$($CONTAINER_CMD ps -a --filter "name=openldap-poc" --format "{{.Names}}" | head -1)
    if [ -z "$LDAP_CONTAINER" ]; then
      echo "ERROR: No LDAP container found!"
      exit 1
    fi
    
    echo "Found LDAP container: $LDAP_CONTAINER"
    LDAP_STATUS=$($CONTAINER_CMD inspect "$LDAP_CONTAINER" --format='{{.State.Status}}' 2>/dev/null || echo "unknown")
    LDAP_HEALTH=$($CONTAINER_CMD inspect "$LDAP_CONTAINER" --format='{{.State.Health.Status}}' 2>/dev/null || echo "none")
    echo "LDAP Container Status: $LDAP_STATUS, Health: $LDAP_HEALTH"
    
    if [ "$LDAP_STATUS" != "running" ]; then
      echo "ERROR: LDAP container is not running!"
      $CONTAINER_CMD logs "$LDAP_CONTAINER" 2>&1 | tail -50
      exit 1
    fi
    
    echo "=== DEBUG: Waiting for LDAP to be ready ==="
    echo "LDAP_URL_PUBLIC=$LDAP_URL_PUBLIC"
    echo "LDAP_BIND_DN=$LDAP_BIND_DN"
    
    for i in {1..60}; do
      if ldapsearch -x -H "$LDAP_URL_PUBLIC" -b "dc=enos,dc=com" -D "$LDAP_BIND_DN" -w "$LDAP_BIND_PASS" -s base "(objectclass=*)" >/dev/null 2>&1; then
        echo "LDAP is fully operational at attempt $i!"
        break
      fi
      
      echo "LDAP readiness check attempt $i/60..."
      
      if [ $i -eq 60 ]; then
        echo "ERROR: LDAP not operational after 60 attempts"
        echo "=== LDAP Container Logs ==="
        $CONTAINER_CMD logs "$LDAP_CONTAINER" 2>&1
        echo "=== Last ldapsearch attempt output ==="
        ldapsearch -x -H "$LDAP_URL_PUBLIC" -b "dc=enos,dc=com" -D "$LDAP_BIND_DN" -w "$LDAP_BIND_PASS" -s base "(objectclass=*)" 2>&1 || true
        exit 1
      fi
      
      sleep 2
    done
    
    echo "=== DEBUG: Testing LDAP connectivity from host ==="
    if command -v ldapsearch > /dev/null 2>&1; then
      ldapsearch -x -H "$LDAP_URL_PUBLIC" -b "dc=enos,dc=com" -D "$LDAP_BIND_DN" -w "$LDAP_BIND_PASS" || echo "LDAP search failed (may need to install ldap-utils)"
    else
      echo "ldapsearch not available, skipping connectivity test"
    fi
    
    echo "=== DEBUG: Final status ==="
    $CONTAINER_CMD ps -a
    curl -v ${var.vault_address}/v1/sys/health 2>&1
    
    echo "=== Running tests ==="
    go test -v -tags=blackbox -timeout=${var.test_timeout} ${var.test_package}
    EOT
  ]
}

output "stdout" {
  description = "Test stdout"
  value       = enos_local_exec.test.stdout
}

output "stderr" {
  description = "Test stderr"
  value       = enos_local_exec.test.stderr
}
