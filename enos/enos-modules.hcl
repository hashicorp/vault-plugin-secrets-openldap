// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

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

// A shim "build module" suitable for use when using locally pre-built artifacts or a zip bundle
// from releases.hashicorp.com. When using a local pre-built artifact it requires the local
// artifact path. When using a release zip it does nothing as you'll need to configure the
// vault_cluster module with release info instead.
module "build_vault_crt" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/build_crt?ref=${var.vault_repo_ref}"
}

// A shim "build module" suitable for use when using locally pre-built artifacts or a zip bundle
// from releases.hashicorp.com. When using a local pre-built artifact it requires the local
// artifact path. When using a release zip it does nothing as you'll need to configure the
// vault_cluster module with release info instead.
module "build_ldap_releases" {
  source = "./modules/build_releases"
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

module "ec2_info" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/ec2_info?ref=${var.vault_repo_ref}"
}

module "get_local_metadata" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/get_local_metadata?ref=${var.vault_repo_ref}"
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

module "vault_wait_for_cluster_unsealed" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/vault_wait_for_cluster_unsealed?ref=${var.vault_repo_ref}"

  vault_install_dir = var.vault_install_dir
}

module "vault_verify_raft_auto_join_voter" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/vault_verify_raft_auto_join_voter?ref=${var.vault_repo_ref}"

  vault_install_dir       = var.vault_install_dir
  vault_cluster_addr_port = global.ports["vault_cluster"]["port"]
}

module "vault_verify_version" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/vault_verify_version?ref=${var.vault_repo_ref}"

  vault_install_dir = var.vault_install_dir
}

module "vault_wait_for_leader" {
  source = "git::https://github.com/hashicorp/vault.git//enos/modules/vault_wait_for_leader?ref=${var.vault_repo_ref}"

  vault_install_dir = var.vault_install_dir
}
