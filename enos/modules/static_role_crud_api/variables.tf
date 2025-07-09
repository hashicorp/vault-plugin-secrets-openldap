variable "vault_leader_ip" {
  type        = string
  description = "Public IP of the Vault leader node"
}

variable "plugin_mount_path" {
  type        = string
  description = "Mount path for the plugin"
}

# LDAP variables for configuration
variable "ldap_host" {
  type        = string
  description = "LDAP IP or hostname"
}

variable "ldap_port" {
  type        = string
  description = "LDAP port"
}

variable "ldap_dn" {
  type        = string
  description = "LDAP Distinguished Name (DN)"
}

variable "ldap_username" {
  type        = string
  description = "LDAP username for authentication"
}

variable "ldap_old_password" {
  type        = string
  description = "LDAP old password"
}

variable "ldap_role_name" {
  type        = string
  description = "LDAP role name to be created"
}

variable "vault_addr" {
  type        = string
  description = "The Vault API address"
}

variable "vault_root_token" {
  type        = string
  description = "The Vault cluster root token"
}