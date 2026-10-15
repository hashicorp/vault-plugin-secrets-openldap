// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

variable "vault_addr" {
  type        = string
  description = "The Vault API address"
}

variable "vault_root_token" {
  type        = string
  description = "The Vault cluster root token"
}

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
  description = "The common DN suffix"
}

variable "ldap_bind_pass" {
  type        = string
  description = "LDAP bind password"
}

variable "ldap_schema" {
  type        = string
  description = "LDAP schema type"
}
