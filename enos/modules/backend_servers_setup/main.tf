# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

terraform {
  required_providers {
    enos = {
      source = "registry.terraform.io/hashicorp-forge/enos"
    }
  }
}

locals {
  ldap_server = {
    domain     = "example.com"
    org        = "example"
    admin_pw   = "adminpassword"
    tag        = var.ldap_tag
    port       = var.ports.ldap.port
    secure_port = var.ports.ldaps.port
    ip_address = var.hosts[0].public_ip
    private_ip = var.hosts[0].private_ip
  }
  ldif_path = "/tmp/seed.ldif"
}

# Step 1: We run install_packages
module "install_packages" {
  source   = "git::https://github.com/hashicorp/vault.git//enos/modules/install_packages"
  hosts    = var.hosts
  packages = var.packages
}

# Step 2: Copy LDIF file for seeding LDAP
resource "enos_file" "seed_ldif" {
  depends_on = [module.install_packages]

  source      = abspath("${path.module}/../../../bootstrap/ldif/seed.ldif")
  destination = local.ldif_path

  transport = {
    ssh = {
      host = local.ldap_server.ip_address
    }
  }
}

# Step 3: Start OpenLDAP Docker container and seed data
resource "enos_remote_exec" "setup_openldap" {
  depends_on = [enos_file.seed_ldif]

  environment = {
    LDAP_DOMAIN   = local.ldap_server.domain
    LDAP_ORG      = local.ldap_server.org
    LDAP_ADMIN_PW = local.ldap_server.admin_pw
    IMAGE_TAG     = local.ldap_server.tag
    LDAP_PORT     = local.ldap_server.port
    LDIF_PATH     = local.ldif_path
  }

  scripts = [abspath("${path.module}/../../../bootstrap/setup-openldap.sh")]

  transport = {
    ssh = {
      host = local.ldap_server.ip_address
    }
  }
}