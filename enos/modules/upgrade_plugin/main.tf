terraform {
  required_providers {
    enos = {
      source = "registry.terraform.io/hashicorp-forge/enos"
    }
  }
}

variable "vault_address" {
  description = "Vault API address (e.g. http://127.0.0.1:8200)"
  type        = string
}

variable "vault_token" {
  description = "Vault root token"
  type        = string
  sensitive   = true
}

variable "vault_container_name" {
  description = "Name of the running Vault Docker container"
  type        = string
}

variable "plugin_binary_path" {
  description = "Absolute path to the candidate plugin binary on the host"
  type        = string
}

variable "plugin_name" {
  description = "Name of the plugin as registered in the Vault plugin catalog"
  type        = string
  default     = "vault-plugin-secrets-openldap"
}

variable "plugin_mount" {
  description = "Secrets engine mount path to reload after the upgrade"
  type        = string
  default     = "ldap"
}

# Upgrade the running plugin without restarting Vault or losing mount state:
#   1. docker cp  — copies the candidate binary into /vault/plugins/ inside
#                   the running container.
#   2. vault plugin register — updates the plugin catalog entry with the new
#                   SHA256 so Vault trusts the new binary.
#   3. vault plugin reload  — hot-swaps the running plugin process; all
#                   existing leases, roles, and configuration are preserved.
resource "enos_local_exec" "upgrade" {
  environment = {
    VAULT_ADDR          = var.vault_address
    VAULT_TOKEN         = var.vault_token
    CONTAINER_NAME      = var.vault_container_name
    PLUGIN_BINARY_PATH  = var.plugin_binary_path
    PLUGIN_NAME         = var.plugin_name
    PLUGIN_MOUNT        = var.plugin_mount
  }

  inline = ["${path.module}/scripts/upgrade-plugin.sh"]
}
