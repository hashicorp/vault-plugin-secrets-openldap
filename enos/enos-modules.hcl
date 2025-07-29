// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

module "autopilot_upgrade_storageconfig" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/autopilot_upgrade_storageconfig?ref=${var.vault_repo_ref}"
}

module "backend_raft" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/backend_raft?ref=${var.vault_repo_ref}"
}

// Bootstrap Vault cluster targets
module "bootstrap_vault_cluster_targets" {
  source = "./modules/ec2_bootstrap_tools"
}

// Find any artifact in Artifactory. Requires the version, revision, and edition.
module "build_vault_artifactory" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/build_artifactory_artifact?ref=${var.vault_repo_ref}"
}

// Find any artifact in Artifactory. Requires the version, revision, and edition.
module "build_ldap_artifactory" {
  source = "./modules/build_artifactory_artifact"
}

// Find any released RPM or Deb in Artifactory. Requires the version, edition, distro, and distro
// version.
module "build_vault_artifactory_package" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/build_artifactory_package?ref=${var.vault_repo_ref}"
}

// Find any released RPM or Deb in Artifactory. Requires the version, edition, distro, and distro
// version.
module "build_ldap_artifactory_package" {
  source = "./modules/build_artifactory_package"
}

// A shim "build module" suitable for use when using locally pre-built artifacts or a zip bundle
// from releases.hashicorp.com. When using a local pre-built artifact it requires the local
// artifact path. When using a release zip it does nothing as you'll need to configure the
// vault_cluster module with release info instead.
module "build_vault_crt" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/build_crt?ref=${var.vault_repo_ref}"
}

// Build the local branch and package it into a zip artifact. Requires the goarch, goos, build tags,
// and bundle path.
module "build_ldap_local" {
  source = "./modules/build_local"
}

// Configure the Vault plugin
module "configure_plugin" {
  source = "./modules/configure_plugin/ldap"
}

// Setup Docker and OpenLDAP on backend server with seed data
module "create_backend_server" {
  source = "./modules/backend_servers_setup"
}

module "create_vpc" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/create_vpc?ref=${var.vault_repo_ref}"

  environment = "ci"
  common_tags = var.tags
}

module "choose_follower_host" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/choose_follower_host?ref=${var.vault_repo_ref}"
}

module "ec2_info" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/ec2_info?ref=${var.vault_repo_ref}"
}

module "get_local_metadata" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/get_local_metadata?ref=${var.vault_repo_ref}"
}

module "generate_dr_operation_token" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/generate_dr_operation_token?ref=${var.vault_repo_ref}"

  vault_install_dir = var.vault_install_dir
}

module "generate_failover_secondary_token" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/generate_failover_secondary_token?ref=${var.vault_repo_ref}"

  vault_install_dir = var.vault_install_dir
}

module "generate_secondary_public_key" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/generate_secondary_public_key?ref=${var.vault_repo_ref}"

  vault_install_dir = var.vault_install_dir
}

module "generate_secondary_token" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/generate_secondary_token?ref=${var.vault_repo_ref}"

  vault_install_dir = var.vault_install_dir
}

module "install_packages" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/install_packages?ref=${var.vault_repo_ref}"
}

module "read_license" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/read_license?ref=${var.vault_repo_ref}"
}

module "replication_data" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/replication_data?ref=${var.vault_repo_ref}"
}

module "restart_vault" {
  source            = "git::https://github.com/hashicorp/vault.git//enos/modules/restart_vault?ref=${var.vault_repo_ref}"
  vault_install_dir = var.vault_install_dir
}

module "seal_awskms" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/seal_awskms?ref=${var.vault_repo_ref}"

  cluster_ssh_keypair = var.aws_ssh_keypair_name
  common_tags         = var.tags
}

module "seal_shamir" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/seal_shamir?ref=${var.vault_repo_ref}"

  cluster_ssh_keypair = var.aws_ssh_keypair_name
  common_tags         = var.tags
}

module "seal_pkcs11" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/seal_pkcs11?ref=${var.vault_repo_ref}"

  cluster_ssh_keypair = var.aws_ssh_keypair_name
  common_tags         = var.tags
}

// Register, and enable the Vault plugin
module "setup_plugin" {
  source = "./modules/setup_plugin"
}

module "shutdown_node" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/shutdown_node?ref=${var.vault_repo_ref}"
}

module "shutdown_multiple_nodes" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/shutdown_multiple_nodes?ref=${var.vault_repo_ref}"
}

module "start_vault" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/start_vault?ref=${var.vault_repo_ref}"

  install_dir = var.vault_install_dir
  log_level   = var.vault_log_level
}

module "stop_vault" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/stop_vault?ref=${var.vault_repo_ref}"
}

// create target instances using ec2:CreateFleet
module "target_ec2_fleet" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/target_ec2_fleet?ref=${var.vault_repo_ref}"

  common_tags  = var.tags
  project_name = var.project_name
  ssh_keypair  = var.aws_ssh_keypair_name
}

// create target instances using ec2:RunInstances
module "target_ec2_instances" {
  source = "./modules/target_ec2_instances"

  common_tags   = var.tags
  ports_ingress = values(global.ports)
  project_name  = var.project_name
  ssh_keypair   = var.aws_ssh_keypair_name
}

// don't create instances but satisfy the module interface
module "target_ec2_shim" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/target_ec2_shim?ref=${var.vault_repo_ref}"

  common_tags   = var.tags
  ports_ingress = values(global.ports)
  project_name  = var.project_name
  ssh_keypair   = var.aws_ssh_keypair_name
}

// create target instances using ec2:RequestSpotFleet
module "target_ec2_spot_fleet" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/target_ec2_spot_fleet?ref=${var.vault_repo_ref}"

  common_tags  = var.tags
  project_name = var.project_name
  ssh_keypair  = var.aws_ssh_keypair_name
}

module "vault_agent" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/vault_agent?ref=${var.vault_repo_ref}"

  vault_install_dir = var.vault_install_dir
  vault_agent_port  = global.ports["vault_agent"]["port"]
}

module "vault_proxy" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/vault_proxy?ref=${var.vault_repo_ref}"

  vault_install_dir = var.vault_install_dir
  vault_proxy_port  = global.ports["vault_proxy"]["port"]
}

module "vault_verify_agent_output" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/vault_verify_agent_output?ref=${var.vault_repo_ref}"
}

module "vault_cluster" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/vault_cluster?ref=${var.vault_repo_ref}"

  install_dir     = var.vault_install_dir
  consul_license  = null
  cluster_tag_key = global.vault_tag_key
  log_level       = var.vault_log_level
}

module "vault_get_cluster_ips" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/vault_get_cluster_ips?ref=${var.vault_repo_ref}"

  vault_install_dir = var.vault_install_dir
}

module "vault_failover_demote_dr_primary" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/vault_failover_demote_dr_primary?ref=${var.vault_repo_ref}"

  vault_install_dir = var.vault_install_dir
}

module "vault_failover_promote_dr_secondary" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/vault_failover_promote_dr_secondary?ref=${var.vault_repo_ref}"

  vault_install_dir = var.vault_install_dir
}

module "vault_failover_update_dr_primary" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/vault_failover_update_dr_primary?ref=${var.vault_repo_ref}"

  vault_install_dir = var.vault_install_dir
}

module "vault_raft_remove_node_and_verify" {
  source            = "git::https://github.com/hashicorp/vault.git//enos/modules/vault_raft_remove_node_and_verify?ref=${var.vault_repo_ref}"
  vault_install_dir = var.vault_install_dir
}

module "vault_raft_remove_peer" {
  source            = "git::https://github.com/hashicorp/vault.git//enos/modules/vault_raft_remove_peer?ref=${var.vault_repo_ref}"
  vault_install_dir = var.vault_install_dir
}

module "vault_setup_dr_primary" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/vault_setup_dr_primary?ref=${var.vault_repo_ref}"

  vault_install_dir = var.vault_install_dir
}

module "vault_setup_perf_primary" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/vault_setup_perf_primary?ref=${var.vault_repo_ref}"

  vault_install_dir = var.vault_install_dir
}

module "vault_setup_replication_secondary" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/vault_setup_replication_secondary?ref=${var.vault_repo_ref}"

  vault_install_dir = var.vault_install_dir
}

module "vault_step_down" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/vault_step_down?ref=${var.vault_repo_ref}"

  vault_install_dir = var.vault_install_dir
}

module "vault_test_ui" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/vault_test_ui?ref=${var.vault_repo_ref}"

  ui_run_tests = var.ui_run_tests
}

module "vault_unseal_replication_followers" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/vault_unseal_replication_followers?ref=${var.vault_repo_ref}"

  vault_install_dir = var.vault_install_dir
}

module "vault_upgrade" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/vault_upgrade?ref=${var.vault_repo_ref}"

  vault_install_dir = var.vault_install_dir
}

module "vault_verify_autopilot" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/vault_verify_autopilot?ref=${var.vault_repo_ref}"

  vault_autopilot_upgrade_status = "await-server-removal"
  vault_install_dir              = var.vault_install_dir
}

module "vault_verify_dr_replication" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/vault_verify_dr_replication?ref=${var.vault_repo_ref}"

  vault_install_dir = var.vault_install_dir
}

module "vault_verify_removed_node" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/vault_verify_removed_node?ref=${var.vault_repo_ref}"

  vault_install_dir = var.vault_install_dir
}

module "vault_verify_removed_node_shim" {
  source            = "git::https://github.com/hashicorp/vault.git//enos/modules/vault_verify_removed_node_shim?ref=${var.vault_repo_ref}"
  vault_install_dir = var.vault_install_dir
}

module "vault_verify_secrets_engines_create" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/vault_verify_secrets_engines/modules/create?ref=${var.vault_repo_ref}"

  create_aws_secrets_engine = var.verify_aws_secrets_engine
  vault_install_dir         = var.vault_install_dir
}

module "vault_verify_secrets_engines_read" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/vault_verify_secrets_engines/modules/read?ref=${var.vault_repo_ref}"

  verify_aws_secrets_engine = var.verify_aws_secrets_engine
  vault_install_dir         = var.vault_install_dir
}

module "vault_verify_default_lcq" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/vault_verify_default_lcq?ref=${var.vault_repo_ref}"

  vault_autopilot_default_max_leases = "300000"
}

module "vault_verify_performance_replication" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/vault_verify_performance_replication?ref=${var.vault_repo_ref}"

  vault_install_dir = var.vault_install_dir
}

module "vault_verify_raft_auto_join_voter" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/vault_verify_raft_auto_join_voter?ref=${var.vault_repo_ref}"

  vault_install_dir       = var.vault_install_dir
  vault_cluster_addr_port = global.ports["vault_cluster"]["port"]
}

module "vault_verify_replication" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/vault_verify_replication?ref=${var.vault_repo_ref}"
}

module "vault_verify_ui" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/vault_verify_ui?ref=${var.vault_repo_ref}"
}

module "vault_verify_undo_logs" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/vault_verify_undo_logs?ref=${var.vault_repo_ref}"

  vault_install_dir = var.vault_install_dir
}

module "vault_wait_for_cluster_unsealed" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/vault_wait_for_cluster_unsealed?ref=${var.vault_repo_ref}"

  vault_install_dir = var.vault_install_dir
}

module "vault_verify_version" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/vault_verify_version?ref=${var.vault_repo_ref}"

  vault_install_dir = var.vault_install_dir
}

module "vault_wait_for_leader" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/vault_wait_for_leader?ref=${var.vault_repo_ref}"

  vault_install_dir = var.vault_install_dir
}

module "vault_wait_for_seal_rewrap" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/vault_wait_for_seal_rewrap?ref=${var.vault_repo_ref}"

  vault_install_dir = var.vault_install_dir
}

module "verify_log_secrets" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/verify_log_secrets?ref=${var.vault_repo_ref}"

  radar_license_path = var.vault_radar_license_path != null ? abspath(var.vault_radar_license_path) : null
}

module "verify_seal_type" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/verify_seal_type?ref=${var.vault_repo_ref}"

  vault_install_dir = var.vault_install_dir
}

module "vault_verify_billing_start_date" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/vault_verify_billing_start_date?ref=${var.vault_repo_ref}"

  vault_install_dir       = var.vault_install_dir
  vault_instance_count    = var.vault_instance_count
  vault_cluster_addr_port = global.ports["vault_cluster"]["port"]
}
