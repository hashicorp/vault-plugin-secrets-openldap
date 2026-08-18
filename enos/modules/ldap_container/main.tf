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
  description = "External LDAP port (must be unique for parallel execution)"
  type        = number
  default     = 389
}

variable "ldaps_port" {
  description = "External LDAPS port (must be unique for parallel execution)"
  type        = number
  default     = 636
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
    external = var.ldap_port
  }

  ports {
    internal = 636
    external = var.ldaps_port
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
  value       = "ldap://127.0.0.1:${var.ldap_port}"
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
