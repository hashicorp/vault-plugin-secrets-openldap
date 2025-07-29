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

variable "plugin_source_type" {
  type        = string
  description = "Plugin Source"
  default     = "local_build"
  validation {
    condition     = contains(["local_build", "registry", "local_path"], var.plugin_source_type)
    error_message = "plugin_source_type must be one of: 'local_build', 'registry', 'local_path'."
  }
}

variable "plugin_dir_vault" {
  type        = string
  description = "Plugin directory on Vault side"
}

variable "plugin_mount_path" {
  type        = string
  description = "Mount path for the plugin"
}

variable "artifactory_release" {
  type = object({
    username = string
    token    = string
    url      = string
    sha256   = string
  })
  description = "The Artifactory release information to install Vault artifacts from Artifactory"
  default     = null
}

variable "hosts" {
  description = "The target machines host addresses to use for the Vault cluster"
  type = map(object({
    ipv6       = string
    private_ip = string
    public_ip  = string
  }))
}

variable "release" {
  type = object({
    version = string
    edition = string
  })
  description = "LDAP release version and edition to install from releases.hashicorp.com"
  default     = null
}

variable "local_artifact_path" {
  type        = string
  description = "The path to a locally built vault artifact to install. It can be a zip archive, RPM, or Debian package"
  default     = null
}