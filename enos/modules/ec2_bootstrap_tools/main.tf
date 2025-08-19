# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

terraform {
  required_providers {
    enos = {
      source = "registry.terraform.io/hashicorp-forge/enos"
    }
  }
}

# Install Shasum on EC2 targets
resource "enos_remote_exec" "install-shasum" {
  for_each = var.hosts
  scripts  = [abspath("${path.module}/scripts/install-shasum.sh")]

  transport = {
    ssh = {
      host = each.value.public_ip
    }
  }
}

# Install OpenLDAP clients on EC2 targets
resource "enos_remote_exec" "install-openldap-clients" {
  for_each = var.hosts

  inline = [
    "sudo yum install -y openldap-clients"
  ]

  transport = {
    ssh = {
      host = each.value.public_ip
    }
  }
}

# Ensure the Vault plugin directory exists
resource "enos_remote_exec" "create_plugin_directory" {
  for_each = var.hosts

  environment = {
    PLUGIN_DIR = var.plugin_dir_vault
  }

  scripts = [abspath("${path.module}/scripts/create-plugin-dir.sh")]

  transport = {
    ssh = {
      host = each.value.public_ip
    }
  }
}

# Add plugin directory to the config file
resource "enos_remote_exec" "add_plugin_directory_to_config" {
  depends_on = [enos_remote_exec.create_plugin_directory]
  for_each   = var.hosts

  inline = [
    "echo \"plugin_directory = \\\"${var.plugin_dir_vault}\\\"\" | sudo tee -a /etc/vault.d/vault.hcl"
  ]

  transport = {
    ssh = {
      host = each.value.public_ip
    }
  }
}

# Restart Vault service on all hosts
resource "enos_remote_exec" "restart_vault" {
  depends_on = [enos_remote_exec.add_plugin_directory_to_config]

  for_each = var.hosts

  inline = [
    "sudo systemctl restart vault"
  ]

  transport = {
    ssh = {
      host = each.value.public_ip
    }
  }
}

# Unseal Vault
resource "enos_remote_exec" "unseal_vault" {
  depends_on = [enos_remote_exec.restart_vault]

  for_each = var.hosts

  scripts = [abspath("${path.module}/scripts/vault-unseal.sh")]

  environment = {
    VAULT_ADDR  = var.vault_addr
    UNSEAL_KEYS = join(",", var.unseal_keys)
    THRESHOLD   = tostring(var.threshold)
  }

  transport = {
    ssh = {
      host = each.value.public_ip
    }
  }
}

# Upload the common logging helper script
resource "enos_file" "logging_script" {
  for_each = var.hosts

  source      = abspath("${path.module}/scripts/logging.sh")
  destination = "/opt/logging.sh"

  transport = {
    ssh = {
      host = each.value.public_ip
    }
  }
}

# # Configure persistent logging environment on remote machines
# resource "enos_remote_exec" "configure_logging_env" {
#   depends_on = [enos_file.logging_script]
#   for_each   = var.hosts
#
#   inline = [
#     "sudo bash -c 'echo export LOG_FILE=\"${var.log_file_path}\" > /etc/profile.d/logging_env.sh'",
#     "sudo bash -c 'echo export BASH_ENV=/opt/logging.sh >> /etc/profile.d/logging_env.sh'"
#   ]
#
#   transport = {
#     ssh = {
#       host = each.value.public_ip
#     }
#   }
# }
