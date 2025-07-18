variable "vault_addr" {
  type        = string
  description = "The Vault API address"
}

variable "vault_root_token" {
  type        = string
  description = "The Vault cluster root token"
}

variable "vault_leader_ip" {
  type        = string
  description = "Public IP of the Vault leader node"
}

variable "plugin_name" {
  type        = string
  description = "Name of the plugin"
}

variable "plugin_dest_dir" {
  type        = string
  description = "Plugin local dir"
}

variable "plugin_source_type" {
  type        = string
  description = "Plugin Source"
  default     = "local_build"
  validation {
    condition     = contains(["local_build", "registry", "local_path"], var.plugin_source_type)
    error_message = "plugin_source_type must be one of: 'local_build', 'registry', 'local_path'."
  }
}

variable "makefile_dir" {
  type        = string
  description = "Plugin Project Makefile directory"
  default     = "$(PWD)"
}

variable "plugin_registry_url" {
  type        = string
  description = "Plugin Releases URL"
}

variable "plugin_local_path" {
  type        = string
  description = "Plugin Binary local path"
}


variable "plugin_dir_vault" {
  type        = string
  description = "Plugin directory on Vault side"
}

variable "plugin_mount_path" {
  type        = string
  description = "Mount path for the plugin"
}

variable "go_os" {
  type        = string
  description = "target machine os, e.g., linux"
}

variable "go_arch" {
  type        = string
  description = "target machine architecture, e.g., amd64"
}