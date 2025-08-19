# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    enos = {
      source = "registry.terraform.io/hashicorp-forge/enos"
    }
  }
}

locals {
  admin_dn = "cn=admin,${var.ldap_base_dn}"
  users_dn = "ou=users,${var.ldap_base_dn}"
  user_dn  = "uid=${var.ldap_username},${local.users_dn}"
}

resource "enos_remote_exec" "static_role_crud_api_test" {
  scripts = ["${path.module}/scripts/static-role.sh"]

  environment = {
    VAULT_ADDR        = var.vault_addr
    VAULT_TOKEN       = var.vault_root_token
    PLUGIN_PATH       = var.plugin_mount_path
    LDAP_HOST         = var.ldap_host
    LDAP_PORT         = var.ldap_port
    LDAP_DN           = local.user_dn
    LDAP_USERNAME     = var.ldap_username
    LDAP_OLD_PASSWORD = var.ldap_user_old_password
    ROLE_NAME         = var.ldap_user_role_name
    LDAP_BIND_DN      = local.admin_dn
    LDAP_BIND_PASS    = var.ldap_bind_pass
    RESTART           = var.restart
  }

  transport = {
    ssh = {
      host = var.vault_leader_ip
    }
  }

}