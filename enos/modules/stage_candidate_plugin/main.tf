terraform {
  required_providers {
    enos = {
      source = "registry.terraform.io/hashicorp-forge/enos"
    }
  }
}

variable "repo_root" {
  description = "Absolute path to the repository root (the directory containing go.mod). The module builds the plugin from source for linux/<host-arch> so the binary is compatible with the Vault container on both arm64 developer machines and amd64 CI runners."
  type        = string
}

variable "go_binary" {
  description = "Absolute path to the go binary used to build the plugin. Defaults to 'go' (resolved via PATH). Override when the enos shell does not inherit the correct PATH (e.g. GVM-managed installations)."
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

# Build the candidate plugin for linux/<host-arch> and write it into the
# staging directory on the host.
#
# GOOS=linux is always required because the Vault container is a Linux image.
# GOARCH is derived from the host machine's architecture at build time so the
# same Enos scenario works on both Apple Silicon (arm64) developer laptops and
# x86-64 GitHub Actions runners (amd64) without any manual override:
#
#   uname -m output → GOARCH
#   arm64 / aarch64 → arm64
#   x86_64          → amd64
#
# On macOS the host and container share the same ISA (arm64), so no true
# cross-compilation occurs and the binary runs natively. On Linux/amd64 CI
# runners the container is also amd64, so again no cross-compilation is needed.
# CGO_ENABLED=0 produces a fully static binary in both cases.
resource "enos_local_exec" "build_and_stage" {
  inline = [
    "mkdir -p '${var.plugin_dir}'",
    # Derive GOARCH from the host kernel's reported machine type.
    # arm64/aarch64 → arm64; x86_64 → amd64; anything else falls back to amd64.
    "HOST_ARCH=$(uname -m); case \"$HOST_ARCH\" in arm64|aarch64) GOARCH=arm64 ;; x86_64) GOARCH=amd64 ;; *) GOARCH=amd64 ;; esac; cd '${var.repo_root}' && CGO_ENABLED=0 GOOS=linux GOARCH=$GOARCH '${var.go_binary}' build -o '${var.plugin_dir}/${var.plugin_name}' ./cmd/${var.plugin_name}/ && echo \"Staged candidate plugin (linux/$GOARCH): ${var.plugin_dir}/${var.plugin_name}\""
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
