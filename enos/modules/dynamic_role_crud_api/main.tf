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
  ldif_files = fileset("${path.module}/ldif", "*")
  file_host_pairs = flatten([
    for i in range(length(var.hosts)) : [
      for file in local.ldif_files : {
        host_index = i
        public_ip  = var.hosts[i].public_ip
        file       = file
      }
    ]
  ])
  file_host_map = {
    for item in local.file_host_pairs :
    "${item["host_index"]}_${item["file"]}" => item
  }
}

# Copy LDIF files to the hosts
resource "enos_file" "ldif_files" {
  for_each    = local.file_host_map
  source      = abspath("${path.module}/ldif/${each.value["file"]}")
  destination = "${var.ldif_path}/${each.value["file"]}"
  transport = {
    ssh = {
      host = each.value["public_ip"]
    }
  }
}

# Execute the dynamic role CRUD API test script on the Vault leader
resource "enos_remote_exec" "dynamic_role_crud_api_test" {
  depends_on = [enos_file.ldif_files]
  scripts    = ["${path.module}/scripts/dynamic-role.sh"]

  environment = {
    VAULT_ADDR  = var.vault_addr
    VAULT_TOKEN = var.vault_root_token
    PLUGIN_PATH = var.plugin_mount_path
    LDAP_HOST   = var.ldap_host
    LDAP_PORT   = var.ldap_port

    ROLE_NAME        = var.ldap_role_name
    LDAP_USER_DN_TPL = var.ldap_user_dn_tpl
    LDIF_PATH        = var.ldif_path
  }

  transport = {
    ssh = {
      host = var.vault_leader_ip
    }
  }

}