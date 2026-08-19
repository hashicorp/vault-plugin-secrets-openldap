terraform {
  required_providers {
    enos = {
      source = "registry.terraform.io/hashicorp-forge/enos"
    }
  }
}

variable "plugin_binary_path" {
  description = "Absolute path to the candidate plugin binary on the host"
  type        = string
}

variable "plugin_name" {
  description = "Name to give the binary inside the plugin directory (must match the Vault plugin catalog name)"
  type        = string
  default     = "vault-plugin-secrets-openldap"
}

variable "plugin_dir" {
  description = "Absolute path to the host directory to install the plugin binary into"
  type        = string
}

# Copy the candidate binary into the plugin directory and make it executable.
# The directory is bind-mounted into the Vault container by the vault_cluster
# module, so the binary is immediately visible inside the container.
resource "enos_local_exec" "install" {
  inline = [
    "mkdir -p '${var.plugin_dir}'",
    "cp '${var.plugin_binary_path}' '${var.plugin_dir}/${var.plugin_name}'",
    "chmod +x '${var.plugin_dir}/${var.plugin_name}'",
    "echo 'Staged candidate plugin: ${var.plugin_dir}/${var.plugin_name}'"
  ]
}

output "plugin_dir" {
  description = "Host path containing the installed candidate plugin binary"
  value       = var.plugin_dir
  depends_on  = [enos_local_exec.install]
}

output "plugin_name" {
  description = "Name of the plugin binary inside the plugin directory"
  value       = var.plugin_name
  depends_on  = [enos_local_exec.install]
}
