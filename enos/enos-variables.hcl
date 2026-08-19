variable "docker_network_name" {
  description = "Name of the Docker network"
  type        = string
  default     = "enos-poc-network"
}

variable "vault_cluster_name" {
  description = "Name of the Vault cluster"
  type        = string
  default     = "vault-poc"
}

variable "vault_license_path" {
  description = "Path to Vault Enterprise license file"
  type        = string
  default     = ""
}

variable "plugin_binary_path" {
  description = "Absolute path to the candidate plugin binary built from this branch"
  type        = string
  default     = ""
}
