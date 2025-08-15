// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

variable "vault_addr" {
  type        = string
  description = "Vault API address"
}

variable "vault_root_token" {
  type        = string
  description = "Vault cluster root token"
}

variable "vault_leader_ip" {
  type        = string
  description = "SSH host/IP of Vault leader for remote exec"
}

variable "plugin_mount_path" {
  type        = string
  description = "Mount path of the LDAP plugin in Vault"
}
