terraform {
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.0"
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
  description = "Port for Vault API"
  type        = number
  default     = 8200
}

variable "plugin_dir" {
  description = "Host directory to bind-mount into /vault/plugins inside the container. Required for the upgrade_plugin module to inject the candidate binary."
  type        = string
  default     = ""
}

locals {
  image_name      = var.vault_edition == "ent" ? "hashicorp/vault-enterprise:${var.vault_version}-ent" : "hashicorp/vault:${var.vault_version}"
  # Hard-coded dev-mode root token. Intentionally not a secret — this token is
  # only used in ephemeral test containers and is never exposed outside the host.
  dev_root_token  = "root-token-for-testing"
}

# Pull Vault image
resource "docker_image" "vault" {
  name         = local.image_name
  keep_locally = true
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
    external = var.vault_port
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

  # Increase shared memory for stability
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
  value       = "http://127.0.0.1:${var.vault_port}"
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
