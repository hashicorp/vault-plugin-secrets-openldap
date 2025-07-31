# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

terraform {
  required_providers {
    enos = {
      source = "registry.terraform.io/hashicorp-forge/enos"
    }
  }
}

variable "plugin_dest_dir" {
  description = "Where to create the zip bundle of the Plugin build"
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

variable "plugin_name" {
  type        = string
  description = "Name of the plugin"
}

variable "makefile_dir" {
  type        = string
  description = "Plugin Project Makefile directory"
  default     = "$(PWD)"
}

variable "artifactory_host" { default = null }
variable "artifactory_repo" { default = null }
variable "artifactory_token" { default = null }
variable "arch" { default = null }
variable "artifact_type" { default = null }
variable "revision" { default = null }
variable "product_version" { default = null }

resource "enos_local_exec" "build" {
  scripts = ["${path.module}/scripts/plugin-build.sh"]

  environment = {
    PLUGIN_NAME  = var.plugin_name
    PLUGIN_DIR   = var.plugin_dest_dir
    MAKEFILE_DIR = var.makefile_dir
    GOARCH       = var.goarch
    GOOS         = var.goos
  }

}
