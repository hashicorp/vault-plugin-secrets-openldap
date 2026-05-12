terraform {
  required_providers {
    enos = {
      source = "registry.terraform.io/hashicorp-forge/enos"
    }
  }
}

variable "vault_address" {
  description = "Vault API address"
  type        = string
}

variable "vault_token" {
  description = "Vault root token"
  type        = string
  sensitive   = true
}

variable "test_package" {
  description = "Go test package path relative to repository root"
  type        = string
}

variable "repo_root" {
  description = "Repository root directory"
  type        = string
}

variable "test_timeout" {
  description = "Test timeout"
  type        = string
  default     = "10m"
}

resource "enos_local_exec" "test" {
  environment = {
    VAULT_ADDR  = var.vault_address
    VAULT_TOKEN = var.vault_token
  }

  inline = [
    "cd ${var.repo_root} && go test -v -timeout=${var.test_timeout} ${var.test_package}"
  ]
}

output "stdout" {
  description = "Test stdout"
  value       = enos_local_exec.test.stdout
}

output "stderr" {
  description = "Test stderr"
  value       = enos_local_exec.test.stderr
}
