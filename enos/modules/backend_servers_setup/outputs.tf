# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

output "state" {
  value = {
    ldap = local.ldap_server
  }
}

output "ldap_ip_address" {
  value = local.ldap_server.private_ip
}

output "ldap_port" {
  value = local.ldap_server.port
}