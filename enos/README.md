# Enos Test Scenarios

This directory contains [Enos](https://github.com/hashicorp/enos) scenarios for
integration-testing the LDAP secrets engine plugin against a live Vault cluster
running in Docker/Podman on your local machine or in CI.

## Contents

- [`enos-scenario-ldap-poc.hcl`](enos-scenario-ldap-poc.hcl) — Smoke scenario: spins up Vault + OpenLDAP and runs the full blackbox test suite. Use this to verify the plugin works end-to-end on a given Vault version.
- [`enos-scenario-plugin-upgrade.hcl`](enos-scenario-plugin-upgrade.hcl) — Upgrade scenario: runs the blackbox suite against the builtin released plugin (Phase 1 baseline), then builds the candidate plugin from the current branch, registers it in the Vault catalog, and re-runs the suite (Phase 2) to catch regressions.

## Prerequisites

| Tool | Min version | Install |
|------|-------------|---------|
| [Enos](https://github.com/hashicorp/enos) | 0.0.37 | `brew install hashicorp/tap/enos` |
| [Terraform](https://developer.hashicorp.com/terraform/install) | 1.2.0 | `brew install hashicorp/tap/terraform` |
| [Docker](https://docs.docker.com/get-docker/) | 20+ | Docker Desktop or `brew install --cask docker` |
| Go | 1.21+ | `brew install go` |
| `ldap-utils` (`ldapsearch`, `ldapadd`) | any | `brew install openldap` |

Verify everything is in place:

```sh
enos version
terraform version
docker info
go version
ldapsearch --version
```

## Vault Enterprise license

The scenarios deploy Vault Enterprise, so a valid license is required.

Set the path to your `.hclic` file via the `vault_license_path` variable (see
[Running a scenario](#running-a-scenario) below). The file is read at plan time
and injected as an environment variable into the Vault container — it is never
written to disk inside the scenario workspace.

> **Note on Vault 2.x:** `2.0.0` is included in the matrix but requires a
> "Vaultlink" license format that is incompatible with the 1.x `VAULT_LICENSE`
> CI secret. The 2.x variant will fail in CI until a separate `VAULT_LICENSE_V2`
> secret is provisioned. It can be run locally with a valid 2.x license via
> `--var vault_license_path=/path/to/vault2.hclic`.

## Running a scenario

All commands must be run from the **`enos/`** directory.

```sh
cd enos
```

### Initialize Terraform providers (first time only)

```sh
mkdir -p .terraform/plugin-cache
terraform init
```

### `ldap_poc` — full blackbox smoke test

Runs the complete blackbox test suite against a single Vault version. This is
the fastest way to verify the plugin works end-to-end locally.

```sh
# Run against a single Vault version
enos scenario run ldap_poc vault_version:1.21.5 \
  --var vault_license_path=/path/to/vault.hclic

# Run all four supported versions in parallel
enos scenario run ldap_poc \
  --var vault_license_path=/path/to/vault.hclic
```

### `plugin_upgrade` — upgrade regression test

Verifies that the candidate plugin (built from the current branch) does not
introduce regressions when upgrading from a released version. The scenario runs
in two phases against the same live Vault cluster:

- **Phase 1 — Baseline:** run the full blackbox suite against the builtin
  released plugin that ships with the Vault image.
- **Phase 2 — Upgrade:** build the candidate plugin from source, register it in
  the Vault catalog, then re-run the full suite. Any failure here is a
  regression introduced by the candidate plugin.

The plugin binary is built for `linux/<host-arch>` at scenario run time by the
`stage_candidate_plugin` module — no pre-built binary is needed.

```sh
# Run against a single Vault version
enos scenario run plugin_upgrade vault_version:1.21.5 \
  --var vault_license_path=/path/to/vault.hclic

# Run all four supported versions in parallel
enos scenario run plugin_upgrade \
  --var vault_license_path=/path/to/vault.hclic
```

### Passing variables

You can supply variables on the command line with `--var` or via a vars file.
Copy the example file and edit it for your machine:

```sh
# Create enos-local.vars.hcl with your settings:
cat > enos-local.vars.hcl <<'EOF'
vault_license_path = "/path/to/vault.hclic"
EOF
```

Then run without `--var`:

```sh
enos scenario run ldap_poc vault_version:1.21.5
```

> `enos-local.vars.hcl` is gitignored — safe to store secrets there locally.

## Available matrix values

Both scenarios share the same `vault_version` matrix axis:

| Value | Vault release |
|-------|--------------|
| `2.0.0` | Vault 2.0.0 Enterprise (requires 2.x license locally; excluded from CI until `VAULT_LICENSE_V2` secret is provisioned) |
| `1.21.5` | Vault 1.21.5 Enterprise |
| `1.20.9` | Vault 1.20.9 Enterprise |
| `1.19.9` | Vault 1.19.9 Enterprise |

Omit the matrix filter to run all variants in parallel:

```sh
enos scenario run ldap_poc --var vault_license_path=/path/to/vault.hclic
```

## Ports used

Each matrix variant binds to a unique set of host ports so all four can run
concurrently without conflict:

| Vault version | Vault API | LDAP | LDAPS |
|--------------|-----------|------|-------|
| `2.0.0` | 8199 | 1389 | 1636 |
| `1.21.5` | 8200 | 1390 | 1637 |
| `1.20.9` | 8201 | 1391 | 1638 |
| `1.19.9` | 8202 | 1392 | 1639 |

## Destroying resources

Enos destroys resources automatically after a successful run. If a run fails or
you interrupt it, clean up manually:

```sh
# Destroy a specific variant
enos scenario destroy plugin_upgrade vault_version:1.21.5 \
  --var vault_license_path=/path/to/vault.hclic

# Or stop all containers and prune networks directly
docker ps -aq | xargs -r docker stop
docker ps -aq | xargs -r docker rm
docker network prune -f
```

## CI

The [`enos-docker-tests`](../.github/workflows/enos-tests.yaml) workflow runs
the `plugin_upgrade` scenario against all supported Vault versions on every pull
request and push to `main`. It uses `ubuntu-latest` (Linux/amd64) runners with
rootless Podman behind a `docker` symlink.

The `stage_candidate_plugin` module detects the host architecture at build time
(`uname -m`) and sets `GOARCH` accordingly, so the same scenario file works on
both Apple Silicon developer machines (arm64) and the amd64 CI runners without
any manual configuration.

## Troubleshooting

**`label is not a valid enos identifier`**
Scenario names must use underscores, not hyphens. Use `ldap_poc` and
`plugin_upgrade`, not `ldap-poc` or `plugin-upgrade`.

**`no scenarios found matching filter`**
Run from the `enos/` directory and double-check the scenario name and matrix
value. List available scenarios with:
```sh
enos scenario list
```

**`exec format error` in Vault logs**
The plugin binary architecture does not match the container's CPU architecture.
This should not happen with the current `stage_candidate_plugin` module, which
auto-detects `GOARCH` from `uname -m`. If you see this error, confirm that
`uname -m` on the host returns `arm64` or `x86_64` and that Go can build for
that target.

**Vault container exits immediately**
The Enterprise image requires a valid license. Confirm `vault_license_path`
points to a non-empty `.hclic` file and that the license format matches the
Vault major version (1.x license for 1.x images). Check the container logs:
```sh
docker logs $(docker ps -aq --filter name=vault-plugin-upgrade)
```

**LDAP not ready / ldapsearch timeouts**
The `osixia/openldap` image can take 10–20 seconds to initialize. The test
script retries for up to 60 seconds. If it still times out, check:
```sh
docker logs $(docker ps -aq --filter name=openldap)
```

**Port already in use**
Another process (or a previous failed run) is holding a port. Find and free it:
```sh
lsof -i :8200   # or whichever port is reported
# then: enos scenario destroy ... or docker rm -f <container>
```

## Module structure

```
enos/
├── enos.hcl                          # Terraform provider config
├── enos-modules.hcl                  # Module registry
├── enos-variables.hcl                # Shared input variables
├── enos-scenario-ldap-poc.hcl        # ldap_poc scenario
├── enos-scenario-plugin-upgrade.hcl  # plugin_upgrade scenario
└── modules/
    ├── docker_network/               # Creates an isolated Docker bridge network
    ├── ldap_container/               # Runs an osixia/openldap container
    ├── vault_cluster/                # Runs a Vault Enterprise dev-mode container
    ├── stage_candidate_plugin/       # Builds the plugin from source and stages it on the host
    ├── upgrade_plugin/               # Registers the candidate binary in the Vault plugin catalog
    └── run_test/                     # Executes the Go blackbox test suite locally
```
