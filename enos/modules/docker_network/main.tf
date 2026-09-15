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

# Derive a unique /16 subnet per Vault version so all matrix variants can run
# concurrently on the same host without Docker network conflicts.
#
# Strategy: take the first 4 hex digits of md5(vault_version), parse them as a
# base-16 integer (0–65535), modulo 96, then add to second-octet base 20. This
# gives a stable subnet in 172.[20,115].0.0/16 — safely within RFC 1918
# 172.16.0.0/12 — for any version string without requiring this file to be
# updated when new versions are added to the matrix.
locals {
  _second_octet = 20 + parseint(substr(md5(var.vault_version), 0, 4), 16) % 96
  subnet        = "172.${local._second_octet}.0.0/16"
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
