# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

terraform {
  required_providers {
    enos = {
      source = "registry.terraform.io/hashicorp-forge/enos"
    }
  }
}

variable "rotation_window" { default = null }

resource "enos_remote_exec" "root_rotation_period_test" {
  scripts = [abspath("${path.module}/scripts/test-root-rotation-period.sh")]
  environment = {
    VAULT_ADDR      = var.vault_addr
    VAULT_TOKEN     = var.vault_root_token
    PLUGIN_PATH     = var.plugin_mount_path
    ROTATION_PERIOD = var.rotation_period
  }
  transport = {
    ssh = {
      host = var.vault_leader_ip
    }
  }
}
