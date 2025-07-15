# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    enos = {
      source = "registry.terraform.io/hashicorp-forge/enos"
    }
  }
}

#
resource "enos_remote_exec" "static_role_crud_api_test" {
  scripts = ["${path.module}/scripts/static-role.sh"]

  environment = {
    VAULT_ADDR        = var.vault_addr
    VAULT_TOKEN       = var.vault_root_token
    PLUGIN_PATH       = var.plugin_mount_path
    LDAP_HOST         = var.ldap_host
    LDAP_PORT         = var.ldap_port
    LDAP_DN           = var.ldap_dn
    LDAP_USERNAME     = var.ldap_username
    LDAP_OLD_PASSWORD = var.ldap_old_password
    ROLE_NAME         = var.ldap_role_name
  }

  transport = {
    ssh = {
      host = var.vault_leader_ip
    }
  }

}