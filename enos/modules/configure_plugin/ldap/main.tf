# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0
terraform {
  required_providers {
    enos = {
      source = "registry.terraform.io/hashicorp-forge/enos"
    }
  }
}

locals {
  admin_dn = "cn=admin,${var.ldap_base_dn}"
  ldap_url = "ldap://${var.ldap_host}:${var.ldap_port}"
  users_dn = "ou=users,${var.ldap_base_dn}"
}

# Configure the plugin
resource "enos_remote_exec" "plugin_configure" {
  scripts = [abspath("${path.module}/scripts/plugin-configure.sh")]
  environment = {
    PLUGIN_PATH    = var.plugin_mount_path
    VAULT_ADDR     = var.vault_addr
    VAULT_TOKEN    = var.vault_root_token
    LDAP_URL       = local.ldap_url
    LDAP_BIND_DN   = local.admin_dn
    LDAP_BIND_PASS = var.ldap_bind_pass
    LDAP_USER_DN   = local.users_dn
    LDAP_SCHEMA    = var.ldap_schema
  }
  transport = {
    ssh = {
      host = var.vault_leader_ip
    }
  }
}