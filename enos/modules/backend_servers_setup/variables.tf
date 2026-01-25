# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

variable "hosts" {
  description = "The target machines host addresses to use for the Vault cluster"
  type = map(object({
    ipv6       = string
    private_ip = string
    public_ip  = string
  }))
}

variable "ldap_tag" {
  type        = string
  description = "OpenLDAP Server Version to use"
  default     = "1.5.0"
}

variable "ports" {
  description = "Port configuration for services"
  type = map(object({
    port        = string
    description = string
  }))
}

variable "packages" {
  type        = list(string)
  description = "A list of packages to install via the target host package manager"
  default     = []
}

variable "vault_repo_ref" {
  type        = string
  description = "The reference to use for the Vault repository"
  default     = "main"
}