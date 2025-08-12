// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

scenario "openldap_restart" {
  description = <<-EOF
    The scenario verifies that the Vault OpenLDAP secrets engine plugin works correctly after a restart of the Vault cluster.

    This scenario creates a Vault cluster with the OpenLDAP secrets engine plugin installed and configured, and starts an OpenLDAP server.
    It then tests the plugin by creating static and dynamic roles, verifying that they can be created, read, updated, and deleted via the Vault API.
    After that, it restarts all Vault nodes and verifies that the plugin still works correctly after the restart.

    # How to run this scenario

    For general instructions on running a scenario, refer to the Enos docs: https://eng-handbook.hashicorp.services/internal-tools/enos/running-a-scenario/
    For troubleshooting tips and common errors, see https://eng-handbook.hashicorp.services/internal-tools/enos/troubleshooting/.

    Variables required for all scenario variants:
      - aws_ssh_private_key_path (more info about AWS SSH keypairs: https://eng-handbook.hashicorp.services/internal-tools/enos/getting-started/#set-your-aws-key-pair-name-and-private-key)
      - aws_ssh_keypair_name
      - vault_build_date*
      - vault_product_version
      - vault_revision*

    * If you don't already know what build date and revision you should be using, see
    https://eng-handbook.hashicorp.services/internal-tools/enos/troubleshooting/#execution-error-expected-vs-got-for-vault-versioneditionrevisionbuild-date.

    Variables required for some scenario variants:
      - artifactory_token (if using `artifact_source:artifactory` in your filter)
      - aws_region (if different from the default value in enos-variables.hcl)
      - distro_version_<distro> (if different from the default version for your target
      distro. See supported distros and default versions in the distro_version_<distro>
      definitions in enos-variables.hcl)
      - vault_artifact_path (the path to where you have a Vault artifact already downloaded,
      if using `artifact_source:crt` in your filter)
      - vault_license_path (if using an ENT edition of Vault)
  EOF

  matrix {
    arch                 = global.archs
    artifact_source      = global.artifact_sources
    ldap_artifact_source = global.ldap_artifact_sources
    artifact_type        = global.artifact_types
    backend              = global.backends
    config_mode          = global.config_modes
    distro               = global.distros
    edition              = global.editions
    ip_version           = global.ip_versions
    seal                 = global.seals

    // Our local builder always creates bundles
    exclude {
      artifact_source      = ["local"]
      ldap_artifact_source = ["local"]
      artifact_type        = ["package"]
    }

    // PKCS#11 can only be used on ent.hsm and ent.hsm.fips1403.
    exclude {
      seal    = ["pkcs11"]
      edition = [for e in matrix.edition : e if !strcontains(e, "hsm")]
    }

    // softhsm packages not available for leap/sles.
    exclude {
      seal   = ["pkcs11"]
      distro = ["leap", "sles"]
    }
  }

  terraform_cli = terraform_cli.default
  terraform     = terraform.default
  providers = [
    provider.aws.default,
    provider.enos.ec2_user,
    provider.enos.ubuntu
  ]

  locals {
    artifact_path      = matrix.artifact_source != "artifactory" ? abspath(var.vault_artifact_path) : null
    ldap_artifact_path = matrix.ldap_artifact_source != "artifactory" ? abspath(var.ldap_artifact_path) : null
    enos_provider = {
      amzn   = provider.enos.ec2_user
      leap   = provider.enos.ec2_user
      rhel   = provider.enos.ec2_user
      sles   = provider.enos.ec2_user
      ubuntu = provider.enos.ubuntu
    }
    manage_service = matrix.artifact_type == "bundle"
  }

  step "build_vault" {
    description = global.description.build_vault
    module      = "build_vault_${matrix.artifact_source}"

    variables {
      build_tags        = var.vault_local_build_tags != null ? var.vault_local_build_tags : global.build_tags[matrix.edition]
      artifact_path     = local.artifact_path
      goarch            = matrix.arch
      goos              = "linux"
      artifactory_host  = matrix.artifact_source == "artifactory" ? var.artifactory_host : null
      artifactory_repo  = matrix.artifact_source == "artifactory" ? var.artifactory_repo : null
      artifactory_token = matrix.artifact_source == "artifactory" ? var.artifactory_token : null
      arch              = matrix.artifact_source == "artifactory" ? matrix.arch : null
      product_version   = var.vault_product_version
      artifact_type     = matrix.artifact_type
      distro            = matrix.artifact_source == "artifactory" ? matrix.distro : null
      edition           = matrix.artifact_source == "artifactory" ? matrix.edition : null
      revision          = var.vault_revision
    }
  }

  step "ec2_info" {
    description = global.description.ec2_info
    module      = module.ec2_info
  }

  step "create_vpc" {
    description = global.description.create_vpc
    module      = module.create_vpc

    variables {
      common_tags = global.tags
      ip_version  = matrix.ip_version
    }
  }

  step "read_vault_license" {
    description = global.description.read_vault_license
    skip_step   = matrix.edition == "ce"
    module      = module.read_license

    variables {
      file_name = global.vault_license_path
    }
  }

  step "create_seal_key" {
    description = global.description.create_seal_key
    module      = "seal_${matrix.seal}"
    depends_on  = [step.create_vpc]

    providers = {
      enos = provider.enos.ubuntu
    }

    variables {
      cluster_id  = step.create_vpc.id
      common_tags = global.tags
    }
  }

  step "create_vault_cluster_targets" {
    description = global.description.create_vault_cluster_targets
    module      = module.target_ec2_instances
    depends_on  = [step.create_vpc]

    providers = {
      enos = local.enos_provider[matrix.distro]
    }

    variables {
      ami_id          = step.ec2_info.ami_ids[matrix.arch][matrix.distro][global.distro_version[matrix.distro]]
      cluster_tag_key = global.vault_tag_key
      common_tags     = global.tags
      seal_key_names  = step.create_seal_key.resource_names
      vpc_id          = step.create_vpc.id
    }
  }

  step "create_vault_cluster" {
    description = global.description.create_vault_cluster
    module      = module.vault_cluster
    depends_on = [
      step.build_vault,
      step.create_vault_cluster_targets,
    ]

    providers = {
      enos = local.enos_provider[matrix.distro]
    }

    verifies = [
      // verified in modules
      quality.vault_artifact_bundle,
      quality.vault_artifact_deb,
      quality.vault_artifact_rpm,
      quality.vault_audit_log,
      quality.vault_audit_socket,
      quality.vault_audit_syslog,
      quality.vault_autojoin_aws,
      quality.vault_config_env_variables,
      quality.vault_config_file,
      quality.vault_config_log_level,
      quality.vault_init,
      quality.vault_license_required_ent,
      quality.vault_listener_ipv4,
      quality.vault_listener_ipv6,
      quality.vault_service_start,
      quality.vault_storage_backend_raft,
      // verified in enos_vault_start resource
      quality.vault_api_sys_config_read,
      quality.vault_api_sys_ha_status_read,
      quality.vault_api_sys_health_read,
      quality.vault_api_sys_host_info_read,
      quality.vault_api_sys_replication_status_read,
      quality.vault_api_sys_seal_status_api_read_matches_sys_health,
      quality.vault_api_sys_storage_raft_autopilot_configuration_read,
      quality.vault_api_sys_storage_raft_autopilot_state_read,
      quality.vault_api_sys_storage_raft_configuration_read,
      quality.vault_cli_status_exit_code,
      quality.vault_service_systemd_notified,
      quality.vault_service_systemd_unit,
    ]

    variables {
      artifactory_release     = matrix.artifact_source == "artifactory" ? step.build_vault.vault_artifactory_release : null
      backend_cluster_name    = null
      backend_cluster_tag_key = global.backend_tag_key
      cluster_name            = step.create_vault_cluster_targets.cluster_name
      config_mode             = matrix.config_mode
      enable_audit_devices    = var.vault_enable_audit_devices
      hosts                   = step.create_vault_cluster_targets.hosts
      install_dir             = global.vault_install_dir[matrix.artifact_type]
      ip_version              = matrix.ip_version
      license                 = matrix.edition != "ce" ? step.read_vault_license.license : null
      local_artifact_path     = local.artifact_path
      manage_service          = local.manage_service
      packages                = concat(global.packages, global.distro_packages[matrix.distro][global.distro_version[matrix.distro]])
      seal_attributes         = step.create_seal_key.attributes
      seal_type               = matrix.seal
      storage_backend         = matrix.backend
    }
  }

  step "bootstrap_vault_cluster_targets" {
    description = global.description.bootstrap_vault_cluster_targets
    module      = module.bootstrap_vault_cluster_targets
    depends_on  = [step.create_vault_cluster]

    providers = {
      enos = local.enos_provider[matrix.distro]
    }

    variables {
      hosts       = step.create_vault_cluster_targets.hosts
      vault_addr  = step.create_vault_cluster.api_addr_localhost
      unseal_keys = step.create_vault_cluster.unseal_keys_b64
      threshold   = step.create_vault_cluster.unseal_threshold
    }
  }

  step "get_local_metadata" {
    description = global.description.get_local_metadata
    skip_step   = matrix.artifact_source != "local"
    module      = module.get_local_metadata
  }

  // Wait for our cluster to elect a leader
  step "wait_for_new_leader" {
    description = global.description.wait_for_cluster_to_have_leader
    module      = module.vault_wait_for_leader
    depends_on = [step.create_vault_cluster,
    step.bootstrap_vault_cluster_targets]

    providers = {
      enos = local.enos_provider[matrix.distro]
    }

    verifies = [
      quality.vault_api_sys_leader_read,
      quality.vault_unseal_ha_leader_election,
    ]

    variables {
      timeout           = 120 // seconds
      ip_version        = matrix.ip_version
      hosts             = step.create_vault_cluster_targets.hosts
      vault_addr        = step.create_vault_cluster.api_addr_localhost
      vault_install_dir = global.vault_install_dir[matrix.artifact_type]
      vault_root_token  = step.create_vault_cluster.root_token
    }
  }

  step "get_vault_cluster_ips" {
    description = global.description.get_vault_cluster_ip_addresses
    module      = module.vault_get_cluster_ips
    depends_on  = [step.wait_for_new_leader]

    providers = {
      enos = local.enos_provider[matrix.distro]
    }

    verifies = [
      quality.vault_api_sys_ha_status_read,
      quality.vault_api_sys_leader_read,
      quality.vault_cli_operator_members,
    ]

    variables {
      hosts             = step.create_vault_cluster_targets.hosts
      ip_version        = matrix.ip_version
      vault_addr        = step.create_vault_cluster.api_addr_localhost
      vault_install_dir = global.vault_install_dir[matrix.artifact_type]
      vault_root_token  = step.create_vault_cluster.root_token
    }
  }


  step "verify_vault_unsealed" {
    description = global.description.verify_vault_unsealed
    module      = module.vault_wait_for_cluster_unsealed
    depends_on  = [step.wait_for_new_leader]

    providers = {
      enos = local.enos_provider[matrix.distro]
    }

    verifies = [
      quality.vault_seal_awskms,
      quality.vault_seal_pkcs11,
      quality.vault_seal_shamir,
    ]

    variables {
      hosts             = step.create_vault_cluster_targets.hosts
      vault_addr        = step.create_vault_cluster.api_addr_localhost
      vault_install_dir = global.vault_install_dir[matrix.artifact_type]
    }
  }

  step "verify_vault_version" {
    description = global.description.verify_vault_version
    module      = module.vault_verify_version
    depends_on  = [step.verify_vault_unsealed]

    providers = {
      enos = local.enos_provider[matrix.distro]
    }

    verifies = [
      quality.vault_api_sys_version_history_keys,
      quality.vault_api_sys_version_history_key_info,
      quality.vault_version_build_date,
      quality.vault_version_edition,
      quality.vault_version_release,
    ]

    variables {
      hosts                 = step.create_vault_cluster_targets.hosts
      vault_addr            = step.create_vault_cluster.api_addr_localhost
      vault_edition         = matrix.edition
      vault_install_dir     = global.vault_install_dir[matrix.artifact_type]
      vault_product_version = matrix.artifact_source == "local" ? step.get_local_metadata.version : var.vault_product_version
      vault_revision        = matrix.artifact_source == "local" ? step.get_local_metadata.revision : var.vault_revision
      vault_build_date      = matrix.artifact_source == "local" ? step.get_local_metadata.build_date : var.vault_build_date
      vault_root_token      = step.create_vault_cluster.root_token
    }
  }

  step "verify_raft_auto_join_voter" {
    description = global.description.verify_raft_cluster_all_nodes_are_voters
    skip_step   = matrix.backend != "raft"
    module      = module.vault_verify_raft_auto_join_voter
    depends_on = [
      step.verify_vault_unsealed,
      step.get_vault_cluster_ips
    ]

    providers = {
      enos = local.enos_provider[matrix.distro]
    }

    verifies = quality.vault_raft_voters

    variables {
      hosts             = step.create_vault_cluster_targets.hosts
      ip_version        = matrix.ip_version
      vault_addr        = step.create_vault_cluster.api_addr_localhost
      vault_install_dir = global.vault_install_dir[matrix.artifact_type]
      vault_root_token  = step.create_vault_cluster.root_token
    }
  }

  step "build_ldap" {
    description = global.description.build_ldap
    module      = "build_ldap_${matrix.ldap_artifact_source}"

    variables {
      goarch            = matrix.arch
      goos              = "linux"
      artifactory_host  = matrix.ldap_artifact_source == "artifactory" ? var.artifactory_host : null
      artifactory_repo  = matrix.ldap_artifact_source == "artifactory" ? var.plugin_artifactory_repo : null
      artifactory_token = matrix.ldap_artifact_source == "artifactory" ? var.artifactory_token : null
      arch              = matrix.ldap_artifact_source == "artifactory" ? matrix.arch : null
      artifact_type     = matrix.ldap_artifact_source == "artifactory" ? "bundle" : null
      product_version   = var.ldap_plugin_version
      revision          = var.ldap_revision
      plugin_name       = var.plugin_name
      makefile_dir      = matrix.ldap_artifact_source == "local" ? var.makefile_dir : null
      plugin_dest_dir   = matrix.ldap_artifact_source == "local" ? var.plugin_dest_dir : null
    }
  }

  step "create_ldap_server_target" {
    description = global.description.create_ldap_server_target
    module      = module.target_ec2_instances
    depends_on  = [step.create_vpc]

    providers = {
      enos = local.enos_provider[matrix.distro]
    }

    variables {
      ami_id          = step.ec2_info.ami_ids[matrix.arch][matrix.distro][global.distro_version[matrix.distro]]
      cluster_tag_key = global.ldap_tag_key
      common_tags     = global.tags
      vpc_id          = step.create_vpc.id
      instance_count  = 1
    }
  }

  step "create_ldap_server" {
    description = global.description.create_ldap_server
    module      = module.create_backend_server
    depends_on  = [step.create_ldap_server_target]

    providers = {
      enos = local.enos_provider[matrix.distro]
    }

    variables {
      hosts     = step.create_ldap_server_target.hosts
      ldap_tag  = var.ldap_tag
      ldap_port = global.ports.ldap.port
    }
  }

  step "setup_plugin" {
    description = global.description.setup_plugin
    module      = module.setup_plugin
    depends_on = [
      step.get_vault_cluster_ips,
      step.create_ldap_server,
      step.verify_vault_unsealed,
      step.build_ldap
    ]

    providers = {
      enos = local.enos_provider[matrix.distro]
    }

    variables {
      artifactory_release = matrix.ldap_artifact_source == "artifactory" ? step.build_ldap.ldap_artifactory_release : null
      release             = matrix.ldap_artifact_source == "releases" ? { version = var.ldap_plugin_version, edition = "ce" } : null
      hosts               = step.create_vault_cluster_targets.hosts
      local_artifact_path = matrix.ldap_artifact_source == "local" ? local.ldap_artifact_path : null


      vault_leader_ip  = step.get_vault_cluster_ips.leader_host.public_ip
      vault_addr       = step.create_vault_cluster.api_addr_localhost
      vault_root_token = step.create_vault_cluster.root_token

      plugin_name       = var.plugin_name
      plugin_dir_vault  = var.plugin_dir_vault
      plugin_mount_path = var.plugin_mount_path
    }
  }

  step "configure_plugin" {
    description = global.description.configure_plugin
    module      = module.configure_plugin
    depends_on  = [step.setup_plugin]

    providers = {
      enos = local.enos_provider[matrix.distro]
    }

    variables {
      vault_leader_ip  = step.get_vault_cluster_ips.leader_host.public_ip
      vault_addr       = step.create_vault_cluster.api_addr_localhost
      vault_root_token = step.create_vault_cluster.root_token

      plugin_mount_path = var.plugin_mount_path
      ldap_host         = step.create_ldap_server.ldap_ip_address
      ldap_port         = step.create_ldap_server.ldap_port
      ldap_base_dn      = var.ldap_base_dn
      ldap_bind_pass    = var.ldap_bind_pass
      ldap_schema       = var.ldap_schema
    }
  }

  step "test_static_role_crud_api" {
    description = global.description.static_role_crud_api
    module      = module.static_role_crud_api
    depends_on  = [step.configure_plugin]

    providers = {
      enos = local.enos_provider[matrix.distro]
    }

    variables {
      vault_leader_ip        = step.get_vault_cluster_ips.leader_host.public_ip
      vault_addr             = step.create_vault_cluster.api_addr_localhost
      vault_root_token       = step.create_vault_cluster.root_token
      plugin_mount_path      = var.plugin_mount_path
      ldap_host              = step.create_ldap_server.ldap_ip_address
      ldap_port              = step.create_ldap_server.ldap_port
      ldap_base_dn           = var.ldap_base_dn
      ldap_bind_pass         = var.ldap_bind_pass
      ldap_user_role_name    = var.ldap_user_role_name
      ldap_username          = var.ldap_username
      ldap_user_old_password = var.ldap_user_old_password
    }
  }

  step "test_dynamic_role_crud_api" {
    description = global.description.dynamic_role_crud_api
    module      = module.dynamic_role_crud_api
    depends_on  = [step.configure_plugin]

    providers = {
      enos = local.enos_provider[matrix.distro]
    }

    variables {
      vault_leader_ip  = step.get_vault_cluster_ips.leader_host.public_ip
      vault_addr       = step.create_vault_cluster.api_addr_localhost
      vault_root_token = step.create_vault_cluster.root_token
      hosts            = step.create_vault_cluster_targets.hosts

      plugin_mount_path                = var.plugin_mount_path
      ldap_host                        = step.create_ldap_server.ldap_ip_address
      ldap_port                        = step.create_ldap_server.ldap_port
      ldap_base_dn                     = var.ldap_base_dn
      dynamic_role_ldif_templates_path = var.dynamic_role_ldif_templates_path
      ldap_dynamic_user_role_name      = var.ldap_dynamic_user_role_name
    }
  }

  step "test_library_crud_api" {
    description = global.description.library_crud_api
    module      = module.library_crud_api
    depends_on = [
      step.configure_plugin,
      step.test_static_role_crud_api
    ]

    providers = {
      enos = local.enos_provider[matrix.distro]
    }

    variables {
      vault_leader_ip       = step.get_vault_cluster_ips.leader_host.public_ip
      vault_addr            = step.create_vault_cluster.api_addr_localhost
      vault_root_token      = step.create_vault_cluster.root_token
      plugin_mount_path     = var.plugin_mount_path
      ldap_host             = step.create_ldap_server.ldap_ip_address
      ldap_port             = step.create_ldap_server.ldap_port
      ldap_base_dn          = var.ldap_base_dn
      library_set_name      = var.library_set_name
      service_account_names = var.service_account_names
    }
  }

  step "verify_log_secrets" {
    skip_step = !var.vault_enable_audit_devices || !var.verify_log_secrets

    description = global.description.verify_log_secrets
    module      = module.verify_log_secrets
    depends_on = [
      step.verify_vault_unsealed,
      step.test_static_role_crud_api,
      step.test_dynamic_role_crud_api
    ]

    providers = {
      enos = local.enos_provider[matrix.distro]
    }

    verifies = [
      quality.vault_audit_log_secrets,
      quality.vault_journal_secrets,
      quality.vault_radar_index_create,
      quality.vault_radar_scan_file,
    ]

    variables {
      audit_log_file_path = step.create_vault_cluster.audit_device_file_path
      leader_host         = step.get_vault_cluster_ips.leader_host
      vault_addr          = step.create_vault_cluster.api_addr_localhost
      vault_root_token    = step.create_vault_cluster.root_token
    }
  }

  step "restart_all_vault_nodes" {
    description = global.description.restart_all_vault_nodes
    module      = module.restart_vault
    depends_on = [
      step.get_vault_cluster_ips,
      step.test_static_role_crud_api,
      step.test_dynamic_role_crud_api,
      step.test_library_crud_api,
      step.verify_raft_auto_join_voter
    ]

    providers = {
      enos = local.enos_provider[matrix.distro]
    }

    variables {
      hosts             = step.create_vault_cluster_targets.hosts
      vault_addr        = step.create_vault_cluster.api_addr_localhost
      vault_install_dir = global.vault_install_dir[matrix.artifact_type]
    }
  }

  step "verify_vault_sealed_after_restart" {
    description = global.description.verify_vault_sealed
    module      = module.vault_wait_for_cluster_sealed
    depends_on = [
      step.restart_all_vault_nodes
    ]

    providers = {
      enos = local.enos_provider[matrix.distro]
    }

    variables {
      hosts             = step.create_vault_cluster_targets.hosts
      vault_addr        = step.create_vault_cluster.api_addr_localhost
      vault_install_dir = global.vault_install_dir[matrix.artifact_type]
    }
  }

  step "unseal_vault" {
    description = global.description.unseal_vault
    module      = module.vault_unseal_replication_followers
    depends_on  = [step.verify_vault_sealed_after_restart]

    providers = {
      enos = local.enos_provider[matrix.distro]
    }

    variables {
      hosts             = step.create_vault_cluster_targets.hosts
      vault_addr        = step.create_vault_cluster.api_addr_localhost
      vault_install_dir = global.vault_install_dir[matrix.artifact_type]
      vault_seal_type   = matrix.seal
      vault_unseal_keys = step.create_vault_cluster.unseal_keys_hex
    }
  }

  step "verify_vault_unsealed_after_restart" {
    description = global.description.verify_vault_unsealed
    module      = module.vault_wait_for_cluster_unsealed
    depends_on  = [step.unseal_vault]

    providers = {
      enos = local.enos_provider[matrix.distro]
    }

    verifies = [
      quality.vault_seal_awskms,
      quality.vault_seal_pkcs11,
      quality.vault_seal_shamir,
    ]

    variables {
      hosts             = step.create_vault_cluster_targets.hosts
      vault_addr        = step.create_vault_cluster.api_addr_localhost
      vault_install_dir = global.vault_install_dir[matrix.artifact_type]
    }
  }

  step "get_vault_cluster_ips_after_restart" {
    description = global.description.get_vault_cluster_ip_addresses
    module      = module.vault_get_cluster_ips
    depends_on  = [step.verify_vault_unsealed_after_restart]

    providers = {
      enos = local.enos_provider[matrix.distro]
    }

    verifies = [
      quality.vault_api_sys_ha_status_read,
      quality.vault_api_sys_leader_read,
      quality.vault_cli_operator_members,
    ]

    variables {
      hosts             = step.create_vault_cluster_targets.hosts
      ip_version        = matrix.ip_version
      vault_addr        = step.create_vault_cluster.api_addr_localhost
      vault_install_dir = global.vault_install_dir[matrix.artifact_type]
      vault_root_token  = step.create_vault_cluster.root_token
    }
  }

  step "test_static_role_crud_api_after_restart" {
    description = global.description.static_role_crud_api
    module      = module.static_role_crud_api
    depends_on  = [step.get_vault_cluster_ips_after_restart]

    providers = {
      enos = local.enos_provider[matrix.distro]
    }

    variables {
      vault_leader_ip        = step.get_vault_cluster_ips_after_restart.leader_host.public_ip
      vault_addr             = step.create_vault_cluster.api_addr_localhost
      vault_root_token       = step.create_vault_cluster.root_token
      plugin_mount_path      = var.plugin_mount_path
      ldap_host              = step.create_ldap_server.ldap_ip_address
      ldap_port              = step.create_ldap_server.ldap_port
      ldap_base_dn           = var.ldap_base_dn
      ldap_bind_pass         = var.ldap_bind_pass
      ldap_user_role_name    = var.ldap_user_role_name
      ldap_username          = var.ldap_username
      ldap_user_old_password = var.ldap_user_old_password
    }
  }

  step "test_dynamic_role_crud_api_after_restart" {
    description = global.description.dynamic_role_crud_api
    module      = module.dynamic_role_crud_api
    depends_on = [
      step.get_vault_cluster_ips_after_restart
    ]

    providers = {
      enos = local.enos_provider[matrix.distro]
    }

    variables {
      vault_leader_ip  = step.get_vault_cluster_ips_after_restart.leader_host.public_ip
      vault_addr       = step.create_vault_cluster.api_addr_localhost
      vault_root_token = step.create_vault_cluster.root_token
      hosts            = step.create_vault_cluster_targets.hosts

      plugin_mount_path                = var.plugin_mount_path
      ldap_host                        = step.create_ldap_server.ldap_ip_address
      ldap_port                        = step.create_ldap_server.ldap_port
      ldap_base_dn                     = var.ldap_base_dn
      dynamic_role_ldif_templates_path = var.dynamic_role_ldif_templates_path
      ldap_dynamic_user_role_name      = var.ldap_dynamic_user_role_name
    }
  }

  step "test_library_crud_api_after_restart" {
    description = global.description.library_crud_api
    module      = module.library_crud_api
    depends_on = [
      step.get_vault_cluster_ips_after_restart,
      step.test_static_role_crud_api_after_restart
    ]

    providers = {
      enos = local.enos_provider[matrix.distro]
    }

    variables {
      vault_leader_ip       = step.get_vault_cluster_ips_after_restart.leader_host.public_ip
      vault_addr            = step.create_vault_cluster.api_addr_localhost
      vault_root_token      = step.create_vault_cluster.root_token
      plugin_mount_path     = var.plugin_mount_path
      ldap_host             = step.create_ldap_server.ldap_ip_address
      ldap_port             = step.create_ldap_server.ldap_port
      ldap_base_dn          = var.ldap_base_dn
      library_set_name      = var.library_set_name
      service_account_names = var.service_account_names
    }
  }

  output "audit_device_file_path" {
    description = "The file path for the file audit device, if enabled"
    value       = step.create_vault_cluster.audit_device_file_path
  }

  output "cluster_name" {
    description = "The Vault cluster name"
    value       = step.create_vault_cluster.cluster_name
  }

  output "hosts" {
    description = "The Vault cluster target hosts"
    value       = step.create_vault_cluster.hosts
  }

  output "private_ips" {
    description = "The Vault cluster private IPs"
    value       = step.create_vault_cluster.private_ips
  }

  output "public_ips" {
    description = "The Vault cluster public IPs"
    value       = step.create_vault_cluster.public_ips
  }

  output "root_token" {
    description = "The Vault cluster root token"
    value       = step.create_vault_cluster.root_token
  }

  output "recovery_key_shares" {
    description = "The Vault cluster recovery key shares"
    value       = step.create_vault_cluster.recovery_key_shares
  }

  output "recovery_keys_b64" {
    description = "The Vault cluster recovery keys b64"
    value       = step.create_vault_cluster.recovery_keys_b64
  }

  output "recovery_keys_hex" {
    description = "The Vault cluster recovery keys hex"
    value       = step.create_vault_cluster.recovery_keys_hex
  }

  output "seal_key_attributes" {
    description = "The Vault cluster seal attributes"
    value       = step.create_seal_key.attributes
  }

  output "unseal_keys_b64" {
    description = "The Vault cluster unseal keys"
    value       = step.create_vault_cluster.unseal_keys_b64
  }

  output "unseal_keys_hex" {
    description = "The Vault cluster unseal keys hex"
    value       = step.create_vault_cluster.unseal_keys_hex
  }
}