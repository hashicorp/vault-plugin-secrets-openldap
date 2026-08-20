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

variable "vault_version" {
  description = "Vault version running alongside this LDAP container. Used to derive unique host ports so all matrix variants can run concurrently without conflicts."
  type        = string
}

variable "container_name" {
  description = "Name of the LDAP container"
  type        = string
  default     = "openldap"
}

variable "ldap_admin_password" {
  description = "LDAP admin password"
  type        = string
  default     = "adminpassword"
  sensitive   = true
}

variable "ldap_port" {
  description = "Host port for LDAP. Defaults to -1, which causes the module to derive a unique port from vault_version so all matrix variants can run concurrently."
  type        = number
  default     = -1
}

variable "ldaps_port" {
  description = "Host port for LDAPS. Defaults to -1, which causes the module to derive a unique port from vault_version so all matrix variants can run concurrently."
  type        = number
  default     = -1
}

# Derive unique host ports per supported Vault version so all matrix variants
# can run concurrently on the same host without port conflicts.
#
#   2.0.0  → ldap 1389  ldaps 1636
#   1.21.x → ldap 1390  ldaps 1637
#   1.20.x → ldap 1391  ldaps 1638
#   1.19.x → ldap 1392  ldaps 1639  (default)
locals {
  ldap_port = var.ldap_port != -1 ? var.ldap_port : (
    var.vault_version == "2.0.0"  ? 1389 :
    var.vault_version == "1.21.5" ? 1390 :
    var.vault_version == "1.20.9" ? 1391 :
                                    1392
  )
  ldaps_port = var.ldaps_port != -1 ? var.ldaps_port : (
    var.vault_version == "2.0.0"  ? 1636 :
    var.vault_version == "1.21.5" ? 1637 :
    var.vault_version == "1.20.9" ? 1638 :
                                    1639
  )
}

# Pull OpenLDAP image
resource "docker_image" "openldap" {
  name         = "osixia/openldap:1.5.0"
  keep_locally = true
}

# Create OpenLDAP container
resource "docker_container" "openldap" {
  name  = var.container_name
  image = docker_image.openldap.image_id

  networks_advanced {
    name = var.network_id
  }

  env = [
    "LDAP_ORGANISATION=Enos",
    "LDAP_DOMAIN=enos.com",
    "LDAP_ADMIN_PASSWORD=${var.ldap_admin_password}",
    "LDAP_CONFIG_PASSWORD=config",
    "LDAP_RFC2307BIS_SCHEMA=false",
    "LDAP_REMOVE_CONFIG_AFTER_SETUP=true",
    "LDAP_TLS_VERIFY_CLIENT=never"
  ]

  ports {
    internal = 389
    external = local.ldap_port
  }

  ports {
    internal = 636
    external = local.ldaps_port
  }

  # Use restart=no for test containers so `terraform destroy` can cleanly
  # remove them without the daemon immediately restarting them.
  restart = "no"

  # Note: Removed healthcheck - osixia/openldap image has issues with Docker healthchecks
  # The test script will wait for LDAP port availability instead
}

output "container_id" {
  description = "ID of the LDAP container"
  value       = docker_container.openldap.id
}

output "container_name" {
  description = "Name of the LDAP container"
  value       = docker_container.openldap.name
}

output "ldap_url" {
  description = "LDAP connection URL (container name for Docker network)"
  value       = "ldap://${docker_container.openldap.name}:389"
}

output "ldap_url_public" {
  description = "LDAP connection URL for host machine (localhost with mapped port)"
  value       = "ldap://127.0.0.1:${local.ldap_port}"
}

output "ldap_bind_dn" {
  description = "LDAP bind DN"
  value       = "cn=admin,dc=enos,dc=com"
}

output "ldap_bind_pass" {
  description = "LDAP bind password"
  value       = var.ldap_admin_password
  sensitive   = true
}
