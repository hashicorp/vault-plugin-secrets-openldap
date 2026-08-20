terraform {
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.0"
    }
  }
}

variable "network_name" {
  description = "Name of the Docker network"
  type        = string
}

variable "vault_version" {
  description = "Vault version running in this network variant. Used to derive a unique subnet so all matrix variants can run concurrently without IP conflicts."
  type        = string
}

# Derive a unique /16 subnet per supported Vault version so all matrix variants
# can run concurrently on the same host without Docker network conflicts.
#
#   2.0.0  → 172.24.0.0/16
#   1.21.x → 172.25.0.0/16
#   1.20.x → 172.26.0.0/16
#   1.19.x → 172.27.0.0/16  (default)
locals {
  subnet = (
    var.vault_version == "2.0.0"  ? "172.24.0.0/16" :
    var.vault_version == "1.21.5" ? "172.25.0.0/16" :
    var.vault_version == "1.20.9" ? "172.26.0.0/16" :
                                    "172.27.0.0/16"
  )
}

resource "docker_network" "main" {
  name   = var.network_name
  driver = "bridge"

  ipam_config {
    subnet = local.subnet
  }
}

output "network_id" {
  description = "ID of the created Docker network"
  value       = docker_network.main.id
}

output "network_name" {
  description = "Name of the created Docker network"
  value       = docker_network.main.name
}
