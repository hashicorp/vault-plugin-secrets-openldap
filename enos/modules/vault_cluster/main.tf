terraform {
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.0"
    }
  }
}

variable "network_id" {
  description = "Docker network ID to attach the container to"
  type        = string
}

variable "cluster_name" {
  description = "Name of the Vault cluster"
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

locals {
  image_name = var.vault_edition == "ent" ? "hashicorp/vault-enterprise:${var.vault_version}-ent" : "hashicorp/vault:${var.vault_version}"
  root_token = "root-token-for-testing"
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

  capabilities {
    add = ["IPC_LOCK"]
  }

  env = concat(
    [
      "VAULT_DEV_ROOT_TOKEN_ID=${local.root_token}",
      "VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200",
      "VAULT_ADDR=http://0.0.0.0:8200",
      "SKIP_SETCAP=true"
    ],
    (var.vault_license != null && var.vault_license != "" && trimspace(var.vault_license) != "") ? ["VAULT_LICENSE=${var.vault_license}"] : []
  )

  # Run in dev mode for simplicity
  command = ["server", "-dev", "-dev-root-token-id=${local.root_token}"]

  # Health check
  healthcheck {
    test         = ["CMD", "vault", "status"]
    interval     = "5s"
    timeout      = "3s"
    retries      = 10
    start_period = "30s"
  }

  # Keep container running
  restart = "always"

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
  description = "Vault root token"
  value       = local.root_token
  sensitive   = true
}

output "vault_internal_address" {
  description = "Vault internal address (for container-to-container communication)"
  value       = "http://${docker_container.vault.name}:8200"
}
