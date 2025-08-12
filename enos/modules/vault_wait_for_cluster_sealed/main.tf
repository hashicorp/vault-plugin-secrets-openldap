# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

terraform {
  required_providers {
    enos = {
      source = "registry.terraform.io/hashicorp-forge/enos"
    }
  }
}

variable "hosts" {
  description = "The Vault cluster instances to verify sealed"
  type = map(object({
    ipv6       = string
    private_ip = string
    public_ip  = string
  }))
}

variable "retry_interval" {
  description = "Seconds to wait between retries"
  type        = number
  default     = 2
}

variable "timeout" {
  description = "Max seconds to wait before timing out"
  type        = number
  default     = 60
}

variable "vault_addr" {
  description = "Vault API address"
  type        = string
}

variable "vault_install_dir" {
  description = "Directory where the Vault binary is installed"
  type        = string
}

resource "enos_remote_exec" "verify_node_sealed" {
  for_each = var.hosts

  scripts = [abspath("${path.module}/scripts/verify-vault-node-sealed.sh")]

  environment = {
    HOST_IPV4         = each.value.public_ip
    HOST_IPV6         = each.value.ipv6
    RETRY_INTERVAL    = var.retry_interval
    TIMEOUT_SECONDS   = var.timeout
    VAULT_ADDR        = var.vault_addr
    VAULT_INSTALL_DIR = var.vault_install_dir
  }

  transport = {
    ssh = {
      host = each.value.public_ip
    }
  }
}