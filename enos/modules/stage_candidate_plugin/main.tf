terraform {
  required_providers {
    enos = {
      source = "registry.terraform.io/hashicorp-forge/enos"
    }
  }
}

variable "repo_root" {
  description = "Absolute path to the repository root (the directory containing go.mod). The module cross-compiles the plugin from source for linux/arm64 so the binary is compatible with the Vault container."
  type        = string
}

variable "go_binary" {
  description = "Absolute path to the go binary to use for cross-compilation. Defaults to 'go' (relies on PATH). Override when the enos shell does not inherit the correct PATH (e.g. GVM-managed installations)."
  type        = string
  default     = "go"
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

# Cross-compile the candidate plugin for linux/arm64 (the architecture of the
# Vault container image) and write it into the staging directory on the host.
#
# CGO_ENABLED=0 + GOOS=linux + GOARCH=arm64 produces a statically-linked Linux
# ELF binary regardless of the host OS. This is required because macOS Mach-O
# binaries cause an "exec format error" inside the Linux container even when
# the host and container share the same arm64 ISA.
resource "enos_local_exec" "build_and_stage" {
  inline = [
    "mkdir -p '${var.plugin_dir}'",
    "cd '${var.repo_root}' && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 '${var.go_binary}' build -o '${var.plugin_dir}/${var.plugin_name}' ./cmd/${var.plugin_name}/",
    "chmod +x '${var.plugin_dir}/${var.plugin_name}'",
    "echo 'Staged candidate plugin (linux/arm64): ${var.plugin_dir}/${var.plugin_name}'"
  ]
}

output "plugin_dir" {
  description = "Absolute host path containing the staged candidate plugin binary"
  value       = var.plugin_dir
  depends_on  = [enos_local_exec.build_and_stage]
}

output "plugin_name" {
  description = "Filename of the candidate plugin binary (matches its Vault catalog entry name)"
  value       = var.plugin_name
  depends_on  = [enos_local_exec.build_and_stage]
}
