// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

variable "vault_leader_ip" {
  type        = string
  description = "Public IP of the Vault leader node"
}

variable "plugin_mount_path" {
  type        = string
  description = "Mount path for the plugin"
}

variable "ldap_host" {
  type        = string
  description = "The LDAP server host"
}

variable "ldap_port" {
  type        = string
  description = "The LDAP server port"
}

variable "ldap_base_dn" {
  type        = string
  description = "The common DN suffix (e.g., dc=example,dc=com)"
}

variable "library_set_name" {
  type        = string
  description = "Name of the LDAP library set to create"
}

variable "service_account_names" {
  type        = list(string)
  description = "List of service account UIDs (under ou=users) for the library set"
}

variable "vault_addr" {
  type        = string
  description = "The Vault API address"
}

variable "vault_root_token" {
  type        = string
  description = "The Vault cluster root token"
}
