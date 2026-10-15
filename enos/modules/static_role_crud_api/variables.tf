variable "vault_leader_ip" {
  type        = string
  description = "Public IP of the Vault leader node"
}

variable "plugin_mount_path" {
  type        = string
  description = "Mount path for the plugin"
}


variable "ldap_host" {
  type        = string
  description = "The LDAP server host"
}

variable "ldap_port" {
  type        = string
  description = "The LDAP server port"
}

variable "ldap_base_dn" {
  type        = string
  description = "The common DN suffix"
}

variable "ldap_bind_pass" {
  type        = string
  description = "LDAP bind password"
}

variable "ldap_username" {
  description = "The username of the LDAP user to create"
  type        = string
}

variable "ldap_user_old_password" {
  description = "The old password of the LDAP user to create"
  type        = string
}

variable "ldap_user_role_name" {
  description = "The name of the LDAP user role to create"
  type        = string
}

variable "vault_addr" {
  type        = string
  description = "The Vault API address"
}

variable "vault_root_token" {
  type        = string
  description = "The Vault cluster root token"
}
