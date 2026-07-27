# Enos Testing for vault-plugin-secrets-openldap

This directory contains Enos scenarios for testing the OpenLDAP secrets plugin with different Vault versions using Docker backend.

## Overview

Enos (End-to-End Operational System) provides infrastructure-as-code testing for Vault plugins. This setup uses Docker containers to create isolated test environments.

## Scenarios

### `ldap_poc`
POC scenario for LDAP plugin testing with Docker backend.

**Matrix Variables:**
- `vault_version`: Vault version to test against
  - `2.0.0` (latest)
  - `1.21.5`
  - `1.20.9`
  - `1.19.9`

**Infrastructure:**
- Docker network (isolated per Vault version)
- OpenLDAP container (osixia/openldap:1.5.0)
- Vault cluster container (dev mode)
- Blackbox test execution

## Local Testing

### Prerequisites
- Docker installed and running
- Terraform >= 1.2.0
- Enos CLI installed
- Go >= 1.21 (for running tests)

### Install Enos CLI
```bash
# macOS
brew tap hashicorp/tap
brew install hashicorp/tap/enos

# Linux
curl -sSL https://releases.hashicorp.com/enos/latest/enos_linux_amd64.zip -o enos.zip
unzip enos.zip
sudo mv enos /usr/local/bin/
```

### List Available Scenarios
```bash
cd enos
enos scenario list
```

### Run a Scenario
```bash
cd enos

# Run with specific Vault version
enos scenario run ldap_poc vault_version=2.0.0

# Run with timeout
enos scenario run ldap_poc \
  --timeout 45m0s \
  vault_version=1.21.5
```

### Destroy a Scenario
```bash
cd enos

# Destroy specific scenario
enos scenario destroy ldap_poc vault_version=2.0.0

# Force destroy if stuck
enos scenario destroy ldap_poc \
  --timeout 10m0s \
  vault_version=2.0.0
```

### View Scenario Output
```bash
cd enos

# Show outputs from a running scenario
enos scenario output ldap_poc vault_version=2.0.0

# Example outputs:
# - vault_address: http://127.0.0.1:8199
# - vault_token: root-token-for-testing
# - ldap_url: ldap://openldap-poc-2.0.0:389
# - ldap_bind_dn: cn=admin,dc=enos,dc=com
```

## CI Integration

The Enos scenarios are integrated into GitHub Actions via `.github/workflows/enos-tests.yaml`.

### Workflow Triggers
- Push to `main` branch
- Pull requests to `main` branch
- Manual dispatch via GitHub UI

### Matrix Testing
The CI workflow runs all 4 Vault versions in parallel:
- Each version gets unique ports and network names
- Prevents resource conflicts
- Faster overall execution

### Environment Variables
The workflow uses `ENOS_VAR_*` environment variables:
- `ENOS_VAR_docker_network_name`: Network name (unique per version)
- `ENOS_VAR_vault_cluster_name`: Cluster name (unique per version)
- `ENOS_VAR_vault_license_path`: Path to Vault Enterprise license

### Artifacts
The workflow uploads:
- **Test Results** (JSON): 7-day retention
- **JUnit Results** (XML): 7-day retention
- **Debug Data**: 30-day retention
- **Failure Summaries**: Markdown tables for aggregation

### Required Secrets
- `VAULT_LICENSE`: Vault Enterprise license (optional, for enterprise tests)
- `SLACK_WEBHOOK_URL`: Slack webhook for failure notifications (optional)

## Modules

### `docker_network`
Creates an isolated Docker bridge network for the test environment.

**Inputs:**
- `network_name`: Name of the Docker network
- `subnet`: Subnet CIDR (default: 172.25.0.0/16)

**Outputs:**
- `network_id`: Docker network ID
- `network_name`: Docker network name

### `ldap_container`
Deploys an OpenLDAP container for testing.

**Inputs:**
- `network_id`: Docker network to attach to
- `container_name`: Container name
- `ldap_domain`: LDAP domain (default: example.org)
- `ldap_admin_password`: Admin password (default: adminpassword)
- `ldap_port`: External LDAP port (default: 389)
- `ldaps_port`: External LDAPS port (default: 636)

**Outputs:**
- `container_id`: Container ID
- `ldap_url`: Internal LDAP URL (for container-to-container)
- `ldap_url_public`: External LDAP URL (for host access)
- `ldap_bind_dn`: Bind DN
- `ldap_bind_pass`: Bind password

### `vault_cluster`
Deploys a Vault cluster in Docker (dev mode).

**Inputs:**
- `network_id`: Docker network to attach to
- `cluster_name`: Cluster name
- `vault_version`: Vault version (e.g., 1.21.5)
- `vault_edition`: Edition (ent or ce)
- `vault_license`: Enterprise license (optional)
- `vault_port`: External API port (default: 8200)

**Outputs:**
- `container_id`: Container ID
- `vault_address`: External Vault address
- `vault_token`: Root token
- `vault_internal_address`: Internal address (for container-to-container)

### `run_test`
Executes Go tests with Vault and LDAP environment configured.

**Inputs:**
- `vault_address`: Vault API address
- `vault_token`: Vault token
- `test_package`: Go test package path
- `repo_root`: Repository root directory
- `test_timeout`: Test timeout (default: 10m)

**Outputs:**
- `stdout`: Test stdout
- `stderr`: Test stderr

## Troubleshooting

### Scenario Won't Start
```bash
# Check Docker is running
docker info

# Check for port conflicts
docker ps -a
netstat -an | grep LISTEN

# Clean up orphaned resources
docker ps -a --filter "name=vault-poc" --format "{{.ID}}" | xargs docker rm -f
docker network ls --filter "name=enos-poc" --format "{{.ID}}" | xargs docker network rm
```

### Scenario Won't Destroy
```bash
# Force destroy with longer timeout
enos scenario destroy ldap_poc \
  --timeout 15m0s \
  vault_version=2.0.0

# Manual cleanup
docker rm -f $(docker ps -a --filter "name=vault-poc-2.0.0" --format "{{.ID}}")
docker rm -f $(docker ps -a --filter "name=openldap-poc-2.0.0" --format "{{.ID}}")
docker network rm enos-poc-network-2.0.0
```

### Container Health Check Failing
```bash
# Check container logs
docker logs openldap-poc-2.0.0
docker logs vault-poc-2.0.0-node

# Check container health
docker inspect openldap-poc-2.0.0 | jq '.[0].State.Health'

# Test LDAP connection manually
ldapsearch -x -H ldap://localhost:389 -b dc=enos,dc=com -D 'cn=admin,dc=enos,dc=com' -w adminpassword
```

### Tests Failing
```bash
# Run tests manually with debug output
cd enos
export VAULT_ADDR=$(enos scenario output ldap_poc vault_version=2.0.0 | jq -r '.vault_address.value')
export VAULT_TOKEN=$(enos scenario output ldap_poc vault_version=2.0.0 | jq -r '.vault_token.value')

cd ..
go test -v -timeout=10m ./blackbox
```

### CI Workflow Failing
1. Check GitHub Actions logs for specific error
2. Look for artifact uploads (debug data, test results)
3. Check if secrets are configured (`VAULT_LICENSE`, `SLACK_WEBHOOK_URL`)
4. Verify Docker is available in runner
5. Check for resource exhaustion (multiple parallel jobs)

## Development

### Adding New Scenarios
1. Create `enos/enos-scenario-<name>.hcl`
2. Define scenario with matrix variables
3. Add steps using existing modules
4. Test locally before committing
5. Update CI workflow if needed

### Modifying Modules
1. Edit module in `enos/modules/<module-name>/main.tf`
2. Update variable descriptions and defaults
3. Test with existing scenarios
4. Update this README with changes

### Updating Vault Versions
The Vault version matrix is defined in `enos/enos-scenario-ldap-poc.hcl`:
```hcl
matrix {
  vault_version = ["2.0.0", "1.21.5", "1.20.9", "1.19.9"]
}
```

To update:
1. Check latest Vault releases
2. Update matrix in scenario file
3. Update CI workflow matrix (should match)
4. Test locally with new versions
5. Commit changes

## References

- [Enos Documentation](https://github.com/hashicorp/enos)
- [Terraform Docker Provider](https://registry.terraform.io/providers/kreuzwerker/docker/latest/docs)
- [OpenLDAP Docker Image](https://github.com/osixia/docker-openldap)
- [Vault Docker Image](https://hub.docker.com/r/hashicorp/vault)
