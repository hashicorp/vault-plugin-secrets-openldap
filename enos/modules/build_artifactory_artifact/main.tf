// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

terraform {
  required_providers {
    enos = {
      source  = "registry.terraform.io/hashicorp-forge/enos"
      version = ">= 0.6.1"
    }
  }
}

variable "artifactory_token" {
  type        = string
  description = "The token to use when connecting to artifactory"
  default     = null
  sensitive   = true
}

variable "artifactory_host" {
  type        = string
  description = "The artifactory host to search for vault artifacts"
  default     = "https://artifactory.hashicorp.engineering/artifactory"
}

variable "artifactory_repo" {
  type        = string
  description = "The artifactory repo to search for vault artifacts"
  default     = "hashicorp-vault-ecosystem-staging-local"
}

variable "product_name" {
  type        = string
  description = "The name of the product for which the plugin is built"
  default     = "vault-plugin-secrets-openldap"
}

variable "plugin_name" {
  type        = string
  description = "Name of the plugin"
}

variable "goarch" {
  type        = string
  description = "The Go architecture target"
  default     = "amd64"
}

variable "goos" {
  type        = string
  description = "The Go OS target"
  default     = "linux"
}

variable "arch" {}
variable "artifact_type" {}
variable "artifact_path" { default = null }
variable "revision" {}
variable "product_version" {}
variable "bundle_path" { default = null }
variable "plugin_dest_dir" { default = null }
variable "makefile_dir" { default = null }

locals {
  // Compose zip filename: plugin_name_version_goos_goarch.zip
  artifact_name = "${var.plugin_name}_${var.product_version}_${var.goos}_${var.goarch}.zip"
}

data "enos_artifactory_item" "ldap" {
  token    = var.artifactory_token
  name     = local.artifact_name
  host     = var.artifactory_host
  repo     = var.artifactory_repo
  path     = "${var.product_name}/*"
  properties = tomap({
    "commit"          = var.revision,
    "product-name"    = var.product_name,
    "product-version" = var.product_version,
  })
}

output "url" {
  value       = data.enos_artifactory_item.ldap.results[0].url
  description = "Artifactory download URL for the LDAP plugin zip"
}

output "sha256" {
  value       = data.enos_artifactory_item.ldap.results[0].sha256
  description = "SHA256 checksum of the LDAP plugin zip"
}

output "size" {
  value       = data.enos_artifactory_item.ldap.results[0].size
  description = "Size in bytes of the LDAP plugin zip"
}

output "name" {
  value       = data.enos_artifactory_item.ldap.results[0].name
  description = "Name of the LDAP plugin artifact"
}

output "ldap_artifactory_release" {
  value = {
    url      = data.enos_artifactory_item.ldap.results[0].url
    sha256   = data.enos_artifactory_item.ldap.results[0].sha256
    token    = var.artifactory_token
    username = null
  }
}