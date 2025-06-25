output "state" {
  value = {
    ldap = local.ldap_server
  }
}

output "ldap_url" {
  value = "ldap://${local.ldap_server.ip_address}:${local.ldap_server.port}"
}