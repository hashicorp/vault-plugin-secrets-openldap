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

variable "plugin_name" {
  description = "Name of the plugin binary and its catalog entry"
  type        = string
  default     = "vault-plugin-secrets-openldap"
}

variable "action" {
  description = "Plugin catalog action to perform: 'register' adds the candidate binary, 'revert' removes it and restores the builtin."
  type        = string

  validation {
    condition     = contains(["register", "revert"], var.action)
    error_message = "action must be one of: register, revert"
  }
}

# vault_container_name and plugin_dir are only required when action = "register".
# They are unused — and intentionally left empty — when action = "revert".
variable "vault_container_name" {
  description = "Name of the running Vault Docker container. Required when action = 'register'."
  type        = string
  default     = ""
}

variable "plugin_dir" {
  description = "Host directory containing the staged candidate plugin binary. Required when action = 'register'."
  type        = string
  default     = ""
}

locals {
  script = "${path.module}/scripts/${var.action}-plugin.sh"
}

# Execute the script that corresponds to the requested action:
#
#   register-plugin.sh — computes the SHA256 of the candidate binary inside the
#     container (placed there via the bind-mount) and updates the Vault plugin
#     catalog entry so the candidate is loaded the next time the mount is enabled.
#
#   revert-plugin.sh — deletes the external catalog entry, removing the candidate
#     override and causing Vault to fall back to the builtin released plugin the
#     next time the mount is enabled. No container restart is required.
resource "enos_local_exec" "run" {
  environment = {
    VAULT_ADDR     = var.vault_address
    VAULT_TOKEN    = var.vault_token
    PLUGIN_NAME    = var.plugin_name
    CONTAINER_NAME = var.vault_container_name
    PLUGIN_DIR     = var.plugin_dir
  }

  inline = [local.script]
}
