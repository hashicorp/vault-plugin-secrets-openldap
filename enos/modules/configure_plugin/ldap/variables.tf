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

# LDAP variables for configuration
variable "ldap_url" {
  type        = string
  description = "LDAP URL, e.g., ldap://<ip>:389"
}

variable "ldap_bind_dn" {
  type        = string
  description = "LDAP Bind DN"
}

variable "ldap_bind_pass" {
  type        = string
  description = "LDAP Bind password"
}

variable "ldap_user_dn" {
  type        = string
  description = "LDAP User DN"
}

variable "ldap_schema" {
  type        = string
  description = "LDAP schema type, e.g., openldap"
}
