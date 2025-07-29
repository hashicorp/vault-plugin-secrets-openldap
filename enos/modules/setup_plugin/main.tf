# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    enos = {
      source = "registry.terraform.io/hashicorp-forge/enos"
    }
  }
}

# Step 1: Install the plugin bundle to the target hosts
resource "enos_bundle_install" "ldap" {
  for_each = var.hosts

  destination = "/tmp/${var.plugin_name}"
  release     = var.release == null ? var.release : merge({ product = "vault-plugin-secrets-openldap" }, var.release)
  artifactory = var.artifactory_release
  path        = var.local_artifact_path

  transport = {
    ssh = {
      host = each.value.public_ip
    }
  }
}

# Step 2: Register the plugin
resource "enos_remote_exec" "plugin_register" {
  depends_on = [enos_bundle_install.ldap]
  scripts    = [abspath("${path.module}/scripts/plugin-register.sh")]
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

# Step 3: Enable the plugin
resource "enos_remote_exec" "plugin_enable" {
  depends_on = [enos_remote_exec.plugin_register]
  scripts    = [abspath("${path.module}/scripts/plugin-enable.sh")]
  environment = {
    PLUGIN_NAME = var.plugin_name
    PLUGIN_PATH = var.plugin_mount_path
    VAULT_ADDR  = var.vault_addr
    VAULT_TOKEN = var.vault_root_token
  }
  transport = {
    ssh = {
      host = var.vault_leader_ip
    }
  }
}