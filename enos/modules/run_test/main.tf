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

variable "ldap_url_private" {
  description = "LDAP URL (private/container network)"
  type        = string
  default     = ""
}

variable "ldap_url_public" {
  description = "LDAP URL (public/host network)"
  type        = string
  default     = ""
}

variable "ldap_bind_dn" {
  description = "LDAP bind DN"
  type        = string
  default     = ""
}

variable "ldap_bind_pass" {
  description = "LDAP bind password"
  type        = string
  sensitive   = true
  default     = ""
}

variable "ldap_username" {
  description = "LDAP username for tests"
  type        = string
  default     = "enos"
}

variable "ldap_admin_pw" {
  description = "LDAP admin password"
  type        = string
  sensitive   = true
  default     = ""
}

resource "enos_local_exec" "test" {
  environment = {
    VAULT_ADDR       = var.vault_address
    VAULT_TOKEN      = var.vault_token
    LDAP_URL_PRIVATE = var.ldap_url_private
    LDAP_URL_PUBLIC  = var.ldap_url_public
    LDAP_BIND_DN     = var.ldap_bind_dn
    LDAP_BIND_PASS   = var.ldap_bind_pass
    LDAP_USERNAME    = var.ldap_username
    LDAP_ADMIN_PW    = var.ldap_admin_pw
    REPO_ROOT        = var.repo_root
    TEST_PACKAGE     = var.test_package
    TEST_TIMEOUT     = var.test_timeout
  }

  inline = ["${path.module}/scripts/run-blackbox-tests.sh"]
}

output "stdout" {
  description = "Test stdout"
  value       = enos_local_exec.test.stdout
}

output "stderr" {
  description = "Test stderr"
  value       = enos_local_exec.test.stderr
}
