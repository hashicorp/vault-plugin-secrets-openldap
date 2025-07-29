# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    enos = {
      source = "registry.terraform.io/hashicorp-forge/enos"
    }
  }
}

# Configure the plugin
resource "enos_remote_exec" "plugin_configure" {
  scripts = [abspath("${path.module}/scripts/plugin-configure.sh")]
  environment = {
    PLUGIN_PATH    = var.plugin_mount_path
    VAULT_ADDR     = var.vault_addr
    VAULT_TOKEN    = var.vault_root_token
    LDAP_URL       = var.ldap_url
    LDAP_BIND_DN   = var.ldap_bind_dn
    LDAP_BIND_PASS = var.ldap_bind_pass
    LDAP_USER_DN   = var.ldap_user_dn
    LDAP_SCHEMA    = var.ldap_schema
  }
  transport = {
    ssh = {
      host = var.vault_leader_ip
    }
  }
}