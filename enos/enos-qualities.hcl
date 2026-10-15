// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

quality "vault_api_sys_config_read" {
  description = <<-EOF
    The v1/sys/config/sanitized Vault API returns sanitized configuration which matches our given
    configuration
  EOF
}

quality "vault_api_sys_ha_status_read" {
  description = "The v1/sys/ha-status Vault API returns the HA status of the cluster"
}

quality "vault_api_sys_health_read" {
  description = <<-EOF
    The v1/sys/health Vault API returns the correct codes depending on the replication and
    'seal-status' of the cluster
  EOF
}

quality "vault_api_sys_host_info_read" {
  description = "The v1/sys/host-info Vault API returns the host info for each node in the cluster"
}

quality "vault_api_sys_leader_read" {
  description = "The v1/sys/leader Vault API returns the cluster leader info"
}

quality "vault_api_sys_replication_status_read" {
  description = <<-EOF
    The v1/sys/replication/status Vault API returns the performance replication status of the
    cluster
  EOF
}

quality "vault_api_sys_seal_status_api_read_matches_sys_health" {
  description = <<-EOF
    The v1/sys/seal-status Vault API and v1/sys/health Vault API agree on the health of each node
    and the cluster
  EOF
}

quality "vault_api_sys_step_down_steps_down" {
  description = <<-EOF
    The v1/sys/step-down Vault API forces the cluster leader to step down and intiates a new leader
    election
  EOF
}

quality "vault_api_sys_storage_raft_autopilot_configuration_read" {
  description = <<-EOF
    The /sys/storage/raft/autopilot/configuration Vault API returns the autopilot configuration of
    the cluster
  EOF
}

quality "vault_api_sys_storage_raft_autopilot_state_read" {
  description = <<-EOF
    The v1/sys/storage/raft/autopilot/state Vault API returns the raft autopilot state of the
    cluster
  EOF
}

quality "vault_api_sys_storage_raft_configuration_read" {
  description = <<-EOF
    The v1/sys/storage/raft/configuration Vault API returns the raft configuration of the cluster
  EOF
}

quality "vault_api_sys_version_history_keys" {
  description = <<-EOF
    The v1/sys/version-history Vault API returns the cluster version history and the 'keys' data
    includes our target version
  EOF
}

quality "vault_api_sys_version_history_key_info" {
  description = <<-EOF
    The v1/sys/version-history Vault API returns the cluster version history and the
    'key_info["$expected_version]' data is present for the expected version and the 'build_date'
    matches the expected build_date.
  EOF
}

quality "vault_artifact_bundle" {
  description = "The candidate binary packaged as a zip bundle is used for testing"
}

quality "vault_artifact_deb" {
  description = "The candidate binary packaged as a deb package is used for testing"
}

quality "vault_artifact_rpm" {
  description = "The candidate binary packaged as an rpm package is used for testing"
}

quality "vault_audit_log" {
  description = "The Vault audit sub-system is enabled with the log and writes to a log"
}

quality "vault_audit_log_secrets" {
  description = "The Vault audit sub-system does not output secret values"
}

quality "vault_audit_socket" {
  description = "The Vault audit sub-system is enabled with the socket and writes to a socket"
}

quality "vault_audit_syslog" {
  description = "The Vault audit sub-system is enabled with the syslog and writes to syslog"
}

quality "vault_autojoin_aws" {
  description = "Vault auto-joins nodes using AWS tag discovery"
}

quality "vault_cli_operator_members" {
  description = "The 'vault operator members' command returns the expected list of members"
}

quality "vault_cli_operator_step_down" {
  description = "The 'vault operator step-down' command forces the cluster leader to step down"
}

quality "vault_cli_status_exit_code" {
  description = <<-EOF
    The 'vault status' command exits with the correct code depending on expected seal status
  EOF
}

quality "vault_config_env_variables" {
  description = "Vault starts when configured primarily with environment variables"
}

quality "vault_config_file" {
  description = "Vault starts when configured primarily with a configuration file"
}

quality "vault_config_log_level" {
  description = "The 'log_level' config stanza modifies its log level"
}

quality "vault_init" {
  description = "Vault initializes the cluster with the given seal parameters"
}

quality "vault_journal_secrets" {
  description = "The Vault systemd journal does not output secret values"
}

quality "vault_license_required_ent" {
  description = "Vault Enterprise requires a license in order to start"
}

quality "vault_listener_ipv4" {
  description = "Vault operates on ipv4 TCP listeners"
}

quality "vault_listener_ipv6" {
  description = "Vault operates on ipv6 TCP listeners"
}

quality "vault_radar_index_create" {
  description = "Vault radar is able to create an index from KVv2 mounts"
}

quality "vault_radar_scan_file" {
  description = "Vault radar is able to scan a file for secrets"
}

quality "vault_raft_voters" {
  description = global.description.verify_raft_cluster_all_nodes_are_voters
}

quality "vault_seal_awskms" {
  description = "Vault auto-unseals with the awskms seal"
}

quality "vault_seal_shamir" {
  description = <<-EOF
    Vault manually unseals with the shamir seal when given the expected number of 'key_shares'
  EOF
}

quality "vault_seal_pkcs11" {
  description = "Vault auto-unseals with the pkcs11 seal"
}

quality "vault_service_start" {
  description = "Vault starts with the configuration"
}

quality "vault_service_systemd_notified" {
  description = "The Vault binary notifies systemd when the service is active"
}

quality "vault_service_systemd_unit" {
  description = "The 'vault.service' systemd unit starts the service"
}

quality "vault_storage_backend_raft" {
  description = "Vault operates using integrated Raft storage"
}

quality "vault_unseal_ha_leader_election" {
  description = "Vault performs a leader election after it is unsealed"
}

quality "vault_version_build_date" {
  description = "Vault's reported build date matches our expectations"
}

quality "vault_version_edition" {
  description = "Vault's reported edition matches our expectations"
}

quality "vault_version_release" {
  description = "Vault's reported release version matches our expectations"
}
