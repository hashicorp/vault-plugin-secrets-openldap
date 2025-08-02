# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

output "state" {
  value = {
    ldap = local.ldap_server
  }
}

output "ldap_url" {
  value = "ldap://${local.ldap_server.ip_address}:${local.ldap_server.port}"
}

output "ldap_ip_address" {
  value = local.ldap_server.ip_address
}

output "ldap_port" {
  value = local.ldap_server.port
}