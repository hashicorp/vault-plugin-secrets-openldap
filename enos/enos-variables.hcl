variable "go_binary" {
  description = <<-EOF
    Absolute path to the go binary used for cross-compiling the candidate plugin.
    Defaults to "go" (resolved via PATH). Override when the enos shell does not
    inherit the correct PATH — e.g. when using a GVM-managed Go installation.
  EOF
  type        = string
  default     = "go"
}

variable "docker_network_name" {
  description = "Base name for the per-variant Docker bridge network. Each matrix cell appends the vault_version to prevent naming conflicts when all variants run concurrently."
  type        = string
  default     = "enos-plugin-upgrade-network"
}

variable "vault_cluster_name" {
  description = "Base name for the per-variant Vault cluster. Each matrix cell appends the vault_version so parallel runs do not collide."
  type        = string
  default     = "vault-plugin-upgrade"
}

variable "vault_license_path" {
  description = "Absolute path to a Vault Enterprise license file (.hclic). Required for enterprise editions; leave empty for community edition."
  type        = string
  default     = ""
}

variable "blackbox_test_timeout" {
  description = "Go test -timeout value for each blackbox test run (baseline and post-upgrade). Increase if tests consistently time out in slow CI environments."
  type        = string
  default     = "5m"
}

