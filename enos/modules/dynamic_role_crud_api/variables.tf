variable "hosts" {
  description = "The target machines host addresses to use for the Vault cluster"
  type = map(object({
    ipv6       = string
    private_ip = string
    public_ip  = string
  }))
}

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

variable "ldap_user_dn_tpl" {
  type        = string
  description = "LDAP user DN template"
}

variable "ldap_role_name" {
  type        = string
  description = "LDAP role name to be created"
}

variable "ldif_path" {
  type        = string
  description = "LDIF files path"
}

variable "vault_addr" {
  type        = string
  description = "The Vault API address"
}

variable "vault_root_token" {
  type        = string
  description = "The Vault cluster root token"
}