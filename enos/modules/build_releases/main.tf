# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

# Shim module since Releases provided things will use the ldap_release variable
variable "bundle_path" {
  default = "/tmp/vault.zip"
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

variable "artifactory_host" { default = null }
variable "artifactory_repo" { default = null }
variable "artifactory_token" { default = null }
variable "arch" { default = null }
variable "artifact_path" { default = null }
variable "artifact_type" { default = null }
variable "revision" { default = null }
variable "makefile_dir" { default = null }
variable "plugin_name" { default = null }
variable "product_version" { default = null }
variable "plugin_dest_dir" { default = null }
