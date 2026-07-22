// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

terraform {
  required_providers {
    enos = {
      source = "registry.terraform.io/hashicorp-forge/enos"
    }
  }
}

resource "enos_remote_exec" "library_crud_api_test" {
  scripts = ["${path.module}/scripts/library.sh"]

  environment = {
    VAULT_ADDR            = var.vault_addr
    VAULT_TOKEN           = var.vault_root_token
    PLUGIN_PATH           = var.plugin_mount_path
    LDAP_HOST             = var.ldap_host
    LDAP_PORT             = var.ldap_port
    LDAP_BASE_DN          = var.ldap_base_dn
    LIBRARY_SET_NAME      = var.library_set_name
    SERVICE_ACCOUNT_NAMES = join(",", var.service_account_names)
  }

  transport = {
    ssh = {
      host = var.vault_leader_ip
    }
  }
}
