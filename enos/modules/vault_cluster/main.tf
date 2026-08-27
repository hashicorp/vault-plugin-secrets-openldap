terraform {
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.0"
    }
    enos = {
      source = "registry.terraform.io/hashicorp-forge/enos"
    }
  }
}

variable "network_id" {
  description = "ID of the Docker network to attach the container to"
  type        = string
}

variable "cluster_name" {
  description = "Name prefix for the Vault cluster. Used to name the Docker container as <cluster_name>-node."
  type        = string
  default     = "vault"
}

variable "vault_version" {
  description = "Vault version to deploy (e.g., 1.18.3)"
  type        = string
}

variable "vault_edition" {
  description = "Vault edition (ent or ce)"
  type        = string
  default     = "ent"
}

variable "vault_license" {
  description = "Vault Enterprise license"
  type        = string
  default     = null
  sensitive   = true
}

variable "vault_port" {
  description = "Host port for the Vault API. Defaults to -1, which causes the module to derive a unique port from vault_version so all matrix variants can run concurrently."
  type        = number
  default     = -1
}

variable "plugin_dir" {
  description = "Host directory to bind-mount into /vault/plugins inside the container. Must exist on the host before the container starts; this module creates it when non-empty. Required for the upgrade_plugin module to inject the candidate binary; pass an empty staging path for scenarios that only need the directory to exist."
  type        = string
  default     = ""
}

# Derive a unique host port per Vault version so all matrix variants can run
# concurrently on the same host without port conflicts.
#
# Strategy: take the first 4 hex digits of md5(vault_version), parse them as a
# base-16 integer (0–65535), modulo 1000, then add to base 8100. This gives a
# stable port in [8100, 8100+999] = [8100, 9099] for any version string without
# requiring this file to be updated when new versions are added to the matrix.
#
# Example derivations (for reference — not hardcoded):
#   2.0.0  → md5 prefix → some offset → e.g. 8199
#   1.21.5 → md5 prefix → some offset → e.g. 8247
#   1.20.9 → md5 prefix → some offset → e.g. 8312
locals {
  image_name = var.vault_edition == "ent" ? "hashicorp/vault-enterprise:${var.vault_version}-ent" : "hashicorp/vault:${var.vault_version}"
  # Hard-coded dev-mode root token. Intentionally not a secret — this token is
  # only used in ephemeral test containers and is never exposed outside the host.
  dev_root_token = "root-token-for-testing"
  vault_port = var.vault_port != -1 ? var.vault_port : (
    8100 + parseint(substr(md5(var.vault_version), 0, 4), 16) % 1000
  )
}

# Pull Vault image
resource "docker_image" "vault" {
  name         = local.image_name
  keep_locally = true
}

# Ensure the plugin directory exists on the host before the container starts.
# The kreuzwerker Docker provider bind-mounts host_path directly; if the path
# does not exist Docker refuses to start the container. In the plugin_upgrade
# scenario the stage_candidate_plugin module creates this directory first, but
# in scenarios that do not stage a binary (e.g. ldap_poc) no prior step creates
# it, so we create it here whenever plugin_dir is set.
resource "enos_local_exec" "create_plugin_dir" {
  count  = var.plugin_dir != "" ? 1 : 0
  inline = ["mkdir -p '${var.plugin_dir}'"]
}

# Create Vault container
resource "docker_container" "vault" {
  name  = "${var.cluster_name}-node"
  image = docker_image.vault.image_id

  networks_advanced {
    name = var.network_id
  }

  ports {
    internal = 8200
    external = local.vault_port
  }

  # Do NOT request IPC_LOCK. GitHub Actions runners use rootless Podman, which
  # cannot grant this capability; the container crashes immediately when the
  # kernel rejects the mlock(2) syscall. VAULT_DISABLE_MLOCK=true makes Vault
  # skip mlock altogether, which is safe in ephemeral test containers.

  env = concat(
    [
      "VAULT_DEV_ROOT_TOKEN_ID=${local.dev_root_token}",
      "VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200",
      "VAULT_ADDR=http://0.0.0.0:8200",
      "VAULT_DISABLE_MLOCK=true",
      "SKIP_SETCAP=true"
    ],
    (var.vault_license != null && var.vault_license != "" && trimspace(var.vault_license) != "") ? ["VAULT_LICENSE=${var.vault_license}"] : []
  )

  # Run in dev mode so Vault auto-initialises and unseals on startup.
  # -dev-plugin-dir registers /vault/plugins as the external plugin directory.
  # This path is bind-mounted from the host staging directory so the
  # register_candidate_plugin step can inject the new binary without
  # restarting the container.
  command = ["server", "-dev", "-dev-root-token-id=${local.dev_root_token}", "-dev-plugin-dir=/vault/plugins"]

  depends_on = [enos_local_exec.create_plugin_dir]

  dynamic "volumes" {
    for_each = var.plugin_dir != "" ? [var.plugin_dir] : []
    content {
      host_path      = volumes.value
      container_path = "/vault/plugins"
      read_only      = false
    }
  }

  # Probe the sys/health endpoint directly. Using "vault status" as the check
  # command is unreliable: it exits non-zero when sealed (exit 2) and may not
  # be on PATH in all image variants, both of which the kreuzwerker provider
  # interprets as an unhealthy container.
  healthcheck {
    test         = ["CMD", "sh", "-c", "wget -qO- http://127.0.0.1:8200/v1/sys/health?standbyok=true || exit 1"]
    interval     = "5s"
    timeout      = "3s"
    retries      = 10
    start_period = "30s"
  }

  # Use restart=no for test containers so `terraform destroy` can cleanly
  # remove them without the daemon immediately restarting them.
  restart = "no"

  # 128 MiB of shared memory prevents OOM-related crashes observed under
  # resource contention when four matrix variants run concurrently.
  shm_size = 128
}

output "container_id" {
  description = "ID of the Vault container"
  value       = docker_container.vault.id
}

output "container_name" {
  description = "Name of the Vault container"
  value       = docker_container.vault.name
}

output "vault_address" {
  description = "Vault API address (127.0.0.1 for IPv4 compatibility)"
  value       = "http://127.0.0.1:${local.vault_port}"
}

output "vault_token" {
  description = "Vault dev-mode root token"
  value       = local.dev_root_token
  sensitive   = true
}

output "vault_internal_address" {
  description = "Vault internal address (for container-to-container communication)"
  value       = "http://${docker_container.vault.name}:8200"
}
