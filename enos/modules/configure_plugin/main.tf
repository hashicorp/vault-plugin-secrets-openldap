# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    enos = {
      source = "registry.terraform.io/hashicorp-forge/enos"
    }
  }
}

# Step 1: Build the plugin locally
resource "enos_local_exec" "plugin_local_build" {
  scripts = ["${path.module}/scripts/plugin-build.sh"]

  environment = {
    PLUGIN_SOURCE_TYPE = var.plugin_source_type
    PLUGIN_NAME = var.plugin_name
    PLUGIN_DIR = var.plugin_dest_dir
    MAKEFILE_DIR = var.makefile_dir
    PLUGIN_REGISTRY_URL = var.plugin_registry_url
    PLUGIN_LOCAL_PATH = var.plugin_local_path
    GOOS = var.go_os
    GOARCH = var.go_arch
  }

}

# Step 2: Copy the plugin to the EC2 instance running the Vault leader
resource "enos_file" "plugin_binary" {
  depends_on = [enos_local_exec.plugin_local_build]
  source      = "${var.plugin_dest_dir}/${var.plugin_name}"
  destination = "/tmp/${var.plugin_name}"

  transport = {
    ssh = {
      host = var.vault_leader_ip
    }
  }
}

# Step 3: Register the plugin
resource "enos_remote_exec" "plugin_register" {
  depends_on = [enos_file.plugin_binary]
  scripts = [abspath("${path.module}/scripts/plugin-register.sh")]
  environment = {
    PLUGIN_BINARY_SRC = "/tmp/${var.plugin_name}"
    PLUGIN_DIR_VAULT  = var.plugin_dir_vault
    PLUGIN_NAME       = var.plugin_name
    VAULT_ADDR        = var.vault_addr
    VAULT_TOKEN       = var.vault_root_token
  }
  transport = {
    ssh = {
      host = var.vault_leader_ip
    }
  }
}

# Step 4: Enable the plugin
resource "enos_remote_exec" "plugin_enable" {
  depends_on = [enos_remote_exec.plugin_register]
  scripts = [abspath("${path.module}/scripts/plugin-enable.sh")]
  environment = {
    PLUGIN_NAME       = var.plugin_name
    PLUGIN_PATH = var.plugin_mount_path
    VAULT_ADDR        = var.vault_addr
    VAULT_TOKEN       = var.vault_root_token
  }
  transport = {
    ssh = {
      host = var.vault_leader_ip
    }
  }
}

# Step 5: Configure the plugin
resource "enos_remote_exec" "plugin_configure" {
  depends_on = [enos_remote_exec.plugin_enable]
  scripts = [abspath("${path.module}/scripts/plugin-configure.sh")]
  environment = {
    PLUGIN_PATH = var.plugin_mount_path
    VAULT_ADDR        = var.vault_addr
    VAULT_TOKEN       = var.vault_root_token
    LDAP_URL          = var.ldap_url
    LDAP_BIND_DN      = var.ldap_bind_dn
    LDAP_BIND_PASS    = var.ldap_bind_pass
    LDAP_USER_DN      = var.ldap_user_dn
    LDAP_SCHEMA       = var.ldap_schema
  }
  transport = {
    ssh = {
      host = var.vault_leader_ip
    }
  }
}