// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

variable "artifactory_token" {
  type        = string
  description = "The token to use when authenticating to artifactory"
  default     = null
  sensitive   = true
}

variable "artifactory_host" {
  type        = string
  description = "The artifactory host to search for vault artifacts"
  default     = "https://artifactory.hashicorp.engineering/artifactory"
}

variable "artifactory_repo" {
  type        = string
  description = "The artifactory repo to search for vault artifacts"
  default     = "hashicorp-crt-stable-local*"
}

variable "aws_region" {
  description = "The AWS region where we'll create infrastructure"
  type        = string
  default     = "us-east-1"
}

variable "aws_ssh_keypair_name" {
  description = "The AWS keypair to use for SSH"
  type        = string
  default     = "enos-ci-ssh-key"
}

variable "aws_ssh_private_key_path" {
  description = "The path to the AWS keypair private key"
  type        = string
  default     = "./support/private_key.pem"
}

variable "distro_version_amzn" {
  description = "The version of Amazon Linux 2 to use"
  type        = string
  default     = "2023" // or "2", though pkcs11 has not been tested with 2
}

variable "distro_version_leap" {
  description = "The version of openSUSE leap to use"
  type        = string
  default     = "15.6"
}

variable "distro_version_rhel" {
  description = "The version of RHEL to use"
  type        = string
  default     = "9.5" // or "8.10"
}

variable "distro_version_sles" {
  description = "The version of SUSE SLES to use"
  type        = string
  default     = "15.6"
}

variable "distro_version_ubuntu" {
  description = "The version of ubuntu to use"
  type        = string
  default     = "24.04" // or "20.04", "22.04"
}

variable "ldap_dynamic_role_ldif_templates_path" {
  description = "LDIF templates path for dynamic role CRUD API tests"
  default     = "/tmp"
}

variable "ldap_artifact_path" {
  description = "Path to CRT generated or local vault.zip bundle"
  type        = string
  default     = "/tmp/vault-plugin-secrets-openldap.zip"
}

variable "ldap_base_dn" {
  type        = string
  description = "The common DN suffix"
  default     = "dc=example,dc=com"
}

variable "ldap_bind_pass" {
  description = "LDAP bind password"
  type        = string
  default     = null
}

variable "ldap_disable_automated_rotation" {
  type        = bool
  default     = false
  description = "Enterprise: cancel upcoming rotations until unset"
}

variable "ldap_dynamic_user_role_name" {
  description = "The name of the LDAP dynamic user role to create"
  type        = string
  default     = "adam"
}

variable "ldap_plugin_version" {
  description = "LDAP plugin version to use"
  type        = string
  default     = null
}

variable "ldap_revision" {
  description = "The git sha of LDAP plugin artifact we are testing"
  type        = string
  default     = null
}

variable "ldap_rotation_period" {
  type        = number
  default     = 0
  description = "Enterprise: time in seconds before rotating the LDAP secret engine root credential. 0 disables rotation"
}

variable "ldap_rotation_window" {
  type        = number
  default     = 0
  description = "Enterprise: max time in seconds to complete scheduled rotation"
}

variable "ldap_schema" {
  description = "LDAP schema type"
  type        = string
  default     = "openldap"
}

variable "ldap_tag" {
  description = "LDAP image tag version"
  type        = string
  default     = "1.3.0"
}

variable "ldap_username" {
  description = "The username of the LDAP user to create"
  type        = string
  default     = "mary.smith"
}

variable "ldap_user_old_password" {
  description = "The old password of the LDAP user to create"
  type        = string
  default     = "defaultpassword"
}

variable "ldap_user_role_name" {
  description = "The name of the LDAP user role to create"
  type        = string
  default     = "mary"
}

variable "ldap_library_set_name" {
  description = "The name of the library set to use for library CRUD API tests"
  type        = string
  default     = "dev-team"
}

variable "makefile_dir" {
  description = "Directory containing the Makefile for plugin build"
  type        = string
  default     = null
}

variable "plugin_artifactory_repo" {
  type        = string
  description = "The artifactory repo to search for vault plugin artifacts"
  default     = "hashicorp-vault-ecosystem-staging-local"
}

variable "plugin_dest_dir" {
  description = "Destination directory for the plugin binary"
  type        = string
  default     = null
}

variable "plugin_dir_vault" {
  description = "Vault server plugin directory"
  type        = string
  default     = "/etc/vault/plugins"
}

variable "plugin_mount_path" {
  description = "Mount path for the plugin in Vault"
  type        = string
  default     = null
}

variable "plugin_name" {
  description = "Name of the Vault plugin to use"
  type        = string
  default     = null
}

variable "project_name" {
  description = "The description of the project"
  type        = string
  default     = "vault-plugin-secrets-openldap-enos-integration"
}

variable "ldap_service_account_names" {
  description = "List of service account names to create for library CRUD API tests"
  type        = list(string)
  default     = ["staticuser", "bob.johnson", "mary.smith"]
}

variable "tags" {
  description = "Tags that will be applied to infrastructure resources that support tagging"
  type        = map(string)
  default     = null
}

variable "terraform_plugin_cache_dir" {
  description = "The directory to cache Terraform modules and providers"
  type        = string
  default     = null
}

variable "ui_test_filter" {
  type        = string
  description = "A test filter to limit the ui tests to execute. Will be appended to the ember test command as '-f=\"<filter>\"'"
  default     = null
}

variable "ui_run_tests" {
  type        = bool
  description = "Whether to run the UI tests or not. If set to false a cluster will be created but no tests will be run"
  default     = true
}

variable "vault_artifact_type" {
  description = "The type of Vault artifact to use when installing Vault from artifactory. It should be 'package' for .deb or .rpm package and 'bundle' for .zip bundles"
  default     = "bundle"
}

variable "vault_artifact_path" {
  description = "Path to CRT generated or local vault.zip bundle"
  type        = string
  default     = "/tmp/vault.zip"
}

variable "vault_build_date" {
  description = "The build date for Vault artifact"
  type        = string
  default     = ""
}

variable "vault_enable_audit_devices" {
  description = "If true every audit device will be enabled"
  type        = bool
  default     = true
}

variable "vault_install_dir" {
  type        = string
  description = "The directory where the Vault binary will be installed"
  default     = "/opt/vault/bin"
}

variable "vault_instance_count" {
  description = "How many instances to create for the Vault cluster"
  type        = number
  default     = 3
}

variable "vault_license_path" {
  description = "The path to a valid Vault enterprise edition license. This is only required for non-ce editions"
  type        = string
  default     = null
}

variable "vault_local_build_tags" {
  description = "The build tags to pass to the Go compiler for builder:local variants"
  type        = list(string)
  default     = null
}

variable "vault_log_level" {
  description = "The server log level for Vault logs. Supported values (in order of detail) are trace, debug, info, warn, and err."
  type        = string
  default     = "trace"
}

variable "vault_product_version" {
  description = "The version of Vault we are testing"
  type        = string
  default     = null
}

variable "vault_radar_license_path" {
  description = "The license for vault-radar which is used to verify the audit log"
  type        = string
  default     = null
}

variable "vault_repo_ref" {
  description = "The Git ref to use for external modules; can be pinned to a specific SHA"
  type        = string
  default     = "main"
}

variable "vault_revision" {
  description = "The git sha of Vault artifact we are testing"
  type        = string
  default     = null
}

variable "verify_aws_secrets_engine" {
  description = "If true we'll verify AWS secrets engines behavior. Because of user creation restrictions in Doormat AWS accounts, only turn this on for CI, as it depends on resources that exist only in those accounts"
  type        = bool
  default     = false
}

variable "verify_log_secrets" {
  description = "If true and var.vault_enable_audit_devices is true we'll verify that the audit log does not contain unencrypted secrets. Requires var.vault_radar_license_path to be set to a valid license file."
  type        = bool
  default     = false
}