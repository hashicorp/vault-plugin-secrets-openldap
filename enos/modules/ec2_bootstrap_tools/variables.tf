variable "hosts" {
  description = "The target machines host addresses to use for the Vault cluster"
  type = map(object({
    ipv6       = string
    private_ip = string
    public_ip  = string
  }))
}

variable "plugin_dir_vault" {
  description = "The directory for Vault plugins"
  type        = string
  default     = "/etc/vault/plugins"
}

variable "vault_addr" {
  description = "The address of the Vault server"
  type        = string
}

variable "unseal_keys" {
  description = "List of Vault unseal keys in base64 format"
  type        = list(string)
}

variable "threshold" {
  description = "Number of unseal keys required to unseal Vault"
  type        = number
}