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

variable "plugin_dir" {
  description = "Host directory containing the staged candidate plugin binary"
  type        = string
}

variable "plugin_name" {
  description = "Name of the plugin binary and its catalog entry"
  type        = string
  default     = "vault-plugin-secrets-openldap"
}

# Register the candidate plugin in the Vault plugin catalog:
#   1. Compute the SHA256 of the binary already present at /vault/plugins/
#      inside the container (written there via the host bind-mount by
#      stage_candidate_plugin).
#   2. Call vault plugin register to update the catalog entry's sha256 field
#      so Vault will trust and load the new binary.
#
# No container restart is required. The plugin directory is bind-mounted from
# the host, so the candidate binary is already on disk inside the container.
# The Phase-2 blackbox tests enable a fresh ldap/ mount for each run and Vault
# will load the candidate binary at that point from the updated catalog entry.
resource "enos_local_exec" "register_plugin" {
  environment = {
    VAULT_ADDR     = var.vault_address
    VAULT_TOKEN    = var.vault_token
    CONTAINER_NAME = var.vault_container_name
    PLUGIN_DIR     = var.plugin_dir
    PLUGIN_NAME    = var.plugin_name
  }

  inline = ["${path.module}/scripts/upgrade-plugin.sh"]
}
