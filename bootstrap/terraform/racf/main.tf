# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: MPL-2.0

terraform {
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = ">= 5.0.0"
    }
  }
}

provider "vault" {
  address         = "http://127.0.0.1:8200"
  skip_tls_verify = true
}

# This resource will run a script during the apply phase to create static RACF
# users on your RACF server
resource "null_resource" "racf_create_static_users" {
  provisioner "local-exec" {
    command = "./scripts/add_users.sh"

    environment = {
      BIND_DN       = var.racf_bind_username
      BIND_PASSWORD = var.racf_bind_password
      LDAP_URL      = var.racf_ldap_url
      USER_DN       = var.racf_user_dn
      GROUP         = var.racf_group
    }
  }
}

# This resource will run a cleanup script during the destroy phase to delete
# static RACF users on your RACF server
resource "null_resource" "racf_cleanup_static_users" {
  # triggers are a workaround to be able to use tf vars
  triggers = {
    bind_dn       = var.racf_bind_username
    bind_password = var.racf_bind_password
    ldap_url      = var.racf_ldap_url
  }

  provisioner "local-exec" {
    when    = destroy
    command = "./scripts/delete_users.sh"

    environment = {
      BIND_DN       = self.triggers.bind_dn
      BIND_PASSWORD = self.triggers.bind_password
      LDAP_URL      = self.triggers.ldap_url
    }
  }
}

# Create the password policy to be RACF-compatible
resource "vault_password_policy" "racf_policy" {
  name   = "racf-policy"
  policy = file("${path.module}/racf_password_policy.hcl")
}

# Mount the RACF secret engine
resource "vault_mount" "openldap_racf" {
  path = "racf"
  # change type to "ldap" if you are using the builtin plugin
  type        = "vault-plugin-secrets-openldap"
  description = "RACF LDAP secrets engine"
}

# Configure the mounted secrets engine with credential_type "phrase"
# We use vault_generic_secret because the native resource does not yet support
# `credential_type`
resource "vault_generic_secret" "racf_config" {
  path = "${vault_mount.openldap_racf.path}/config"

  data_json = jsonencode({
    binddn          = var.racf_bind_username
    bindpass        = var.racf_bind_password
    url             = var.racf_ldap_url
    userdn          = var.racf_user_dn
    schema          = "racf"
    credential_type = "phrase"
    password_policy = vault_password_policy.racf_policy.name
  })
}

# Create 10 static roles: user0...user9
resource "vault_ldap_secret_backend_static_role" "racf_static_roles" {
  depends_on = [vault_generic_secret.racf_config, null_resource.racf_create_static_users]
  mount      = vault_mount.openldap_racf.path
  count      = 10

  username        = "USER${count.index}"
  role_name       = "user${count.index}"
  rotation_period = "60"
}
